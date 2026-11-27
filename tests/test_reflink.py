import errno
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from coldcleaner import cli, hosts, reflink

GIT_ENV = {
    'GIT_CONFIG_GLOBAL': os.devnull,
    'GIT_CONFIG_NOSYSTEM': '1',
    'GIT_AUTHOR_NAME': 'Test',
    'GIT_AUTHOR_EMAIL': 'test@localhost',
    'GIT_COMMITTER_NAME': 'Test',
    'GIT_COMMITTER_EMAIL': 'test@localhost',
}


def run_git(repo, *args):
    env = {**os.environ, **GIT_ENV}
    subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True, env=env)


def make_worktree_fixture(root):
    main = root / 'repo-main'
    main.mkdir()
    run_git(main, 'init', '-q', '-b', 'main')
    (main / 'large.bin').write_bytes(b'A' * 8192)
    os.chmod(main / 'large.bin', 0o755)
    (main / 'same_size_diff.bin').write_bytes(b'B' * 6144)
    (main / 'small.txt').write_bytes(b'tiny')
    (main / 'sub').mkdir()
    (main / 'sub' / 'shared.dat').write_bytes(b'C' * 12288)
    os.chmod(main / 'sub' / 'shared.dat', 0o640)
    (main / '.gitignore').write_text('node_modules/\n', encoding='utf-8')
    run_git(main, 'add', '.')
    run_git(main, 'commit', '-qm', 'initial')

    wt1 = root / 'repo-wt1'
    run_git(main, 'worktree', 'add', '-q', '-b', 'feat-1', str(wt1))

    dep_bytes = b'D' * 16384
    for wt in (main, wt1):
        dep = wt / 'node_modules' / 'pkg' / 'index.js'
        dep.parent.mkdir(parents=True, exist_ok=True)
        dep.write_bytes(dep_bytes)

    (wt1 / 'same_size_diff.bin').write_bytes(b'X' * 6144)
    run_git(wt1, 'add', 'same_size_diff.bin')
    run_git(wt1, 'commit', '-qm', 'change file')

    return main, wt1


def fake_fideduperange_same(calls):
    def handler(src_fd, buf):
        src_off, src_len, dest_count, _, _ = struct.unpack_from('=QQHHI', buf, 0)
        dst_fd, dst_off, _, _, _ = struct.unpack_from('=qQQiI', buf, 24)
        calls.append((src_fd, dst_fd, src_off, dst_off, src_len, dest_count))
        src_bytes = os.pread(src_fd, src_len, src_off)
        dst_bytes = os.pread(dst_fd, src_len, dst_off)
        if src_bytes == dst_bytes:
            struct.pack_into('=qQQiI', buf, 24, dst_fd, dst_off, len(src_bytes), reflink.FILE_DEDUPE_RANGE_SAME, 0)
        else:
            struct.pack_into('=qQQiI', buf, 24, dst_fd, dst_off, 0, reflink.FILE_DEDUPE_RANGE_DIFFERS, 0)
    return handler


class ReflinkDedupeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.main, self.wt1 = make_worktree_fixture(self.root)

    def test_dry_run_reports_exact_candidates_without_mutating_files(self):
        target_files = [
            self.wt1 / 'large.bin',
            self.wt1 / 'sub' / 'shared.dat',
            self.wt1 / 'node_modules' / 'pkg' / 'index.js',
        ]
        before = {p: (p.lstat().st_ino, p.lstat().st_mtime_ns, p.read_bytes()) for p in target_files}

        result = reflink.dedupe([str(self.root)], apply=False, backend_detector=lambda _: 'linux-fideduperange')

        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['mode'], 'dry-run')
        self.assertEqual(result['backend'], 'linux-fideduperange')
        self.assertTrue(result['apply_supported'])
        self.assertEqual(result['worktree_groups'], 1)
        self.assertEqual(result['worktrees_scanned'], 2)
        self.assertEqual(result['candidate_files'], 3)
        self.assertEqual(result['relinked_files'], 0)
        self.assertEqual(result['reclaimable_bytes'], 8192 + 12288 + 16384)
        self.assertEqual(result['reclaimed_bytes'], 0)
        self.assertEqual(result['skipped']['content_differs'], 1)
        self.assertGreaterEqual(result['skipped']['below_min_size'], 2)
        self.assertGreaterEqual(result['skipped']['git_metadata'], 2)
        self.assertEqual(
            {item['target'] for item in result['candidates']},
            {str(p) for p in target_files},
        )
        self.assertTrue(all(item['action'] == 'would reflink' for item in result['candidates']))
        for p, expected in before.items():
            self.assertEqual((p.lstat().st_ino, p.lstat().st_mtime_ns, p.read_bytes()), expected)

    def test_apply_linux_fideduperange_preserves_inode_metadata_and_bytes_in_place(self):
        calls = []
        large = self.wt1 / 'large.bin'
        shared = self.wt1 / 'sub' / 'shared.dat'
        os.chmod(large, 0o755)
        os.chmod(shared, 0o640)
        orig_large_st = large.lstat()
        orig_shared_st = shared.lstat()
        orig_git_file_ino = (self.wt1 / '.git').lstat().st_ino
        orig_diff_ino = (self.wt1 / 'same_size_diff.bin').lstat().st_ino

        with patch.object(reflink, '_fideduperange_ioctl', side_effect=fake_fideduperange_same(calls)), \
                patch.object(reflink, 'extents_shared', return_value=False):
            result = reflink.dedupe([str(self.root)], apply=True, backend_detector=lambda _: 'linux-fideduperange')

        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['mode'], 'apply')
        self.assertEqual(result['backend'], 'linux-fideduperange')
        self.assertTrue(result['apply_supported'])
        self.assertEqual(result['candidate_files'], 3)
        self.assertEqual(result['relinked_files'], 3)
        self.assertEqual(result['reclaimed_bytes'], 8192 + 12288 + 16384)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(item['action'] == 'reflinked' for item in result['candidates']))

        self.assertEqual(large.lstat().st_ino, orig_large_st.st_ino)
        self.assertEqual(large.lstat().st_gid, orig_large_st.st_gid)
        self.assertEqual(stat.S_IMODE(large.lstat().st_mode), 0o755)
        self.assertEqual(shared.lstat().st_ino, orig_shared_st.st_ino)
        self.assertEqual(shared.lstat().st_gid, orig_shared_st.st_gid)
        self.assertEqual(stat.S_IMODE(shared.lstat().st_mode), 0o640)
        self.assertEqual(large.read_bytes(), b'A' * 8192)
        self.assertEqual(shared.read_bytes(), b'C' * 12288)

        self.assertEqual((self.wt1 / '.git').lstat().st_ino, orig_git_file_ino)
        self.assertEqual((self.wt1 / 'same_size_diff.bin').lstat().st_ino, orig_diff_ino)
        self.assertEqual((self.wt1 / 'same_size_diff.bin').read_bytes(), b'X' * 6144)

    def test_linux_fideduperange_concurrent_save_returns_differs_without_data_loss(self):
        large = self.wt1 / 'large.bin'
        orig_ino = large.lstat().st_ino

        def concurrent_editor_write(src_fd, buf):
            src_off, src_len, _, _, _ = struct.unpack_from('=QQHHI', buf, 0)
            dst_fd, dst_off, _, _, _ = struct.unpack_from('=qQQiI', buf, 24)
            if os.fstat(dst_fd).st_ino == orig_ino:
                large.write_bytes(b'E' * 8192)
                struct.pack_into('=qQQiI', buf, 24, dst_fd, dst_off, 0, reflink.FILE_DEDUPE_RANGE_DIFFERS, 0)
                return
            struct.pack_into('=qQQiI', buf, 24, dst_fd, dst_off, src_len, reflink.FILE_DEDUPE_RANGE_SAME, 0)

        with patch.object(reflink, '_fideduperange_ioctl', side_effect=concurrent_editor_write), \
                patch.object(reflink, 'extents_shared', return_value=False):
            result = reflink.dedupe([str(self.root)], apply=True, backend_detector=lambda _: 'linux-fideduperange')

        self.assertEqual(large.read_bytes(), b'E' * 8192)
        self.assertEqual(large.lstat().st_ino, orig_ino)
        self.assertEqual(result['skipped'].get('changed_during_reflink'), 1)
        self.assertEqual(result['relinked_files'], 2)

    def test_linux_fideduperange_loops_across_partial_chunks(self):
        offsets = []

        def chunked_ioctl(src_fd, buf):
            src_off, src_len, _, _, _ = struct.unpack_from('=QQHHI', buf, 0)
            dst_fd, dst_off, _, _, _ = struct.unpack_from('=qQQiI', buf, 24)
            offsets.append((src_off, dst_off, src_len))
            step = min(4096, src_len)
            struct.pack_into('=qQQiI', buf, 24, dst_fd, dst_off, step, reflink.FILE_DEDUPE_RANGE_SAME, 0)

        with patch.object(reflink, '_fideduperange_ioctl', side_effect=chunked_ioctl), \
                patch.object(reflink, 'extents_shared', return_value=False):
            result = reflink.dedupe([str(self.root)], apply=True, min_bytes=16384,
                                    backend_detector=lambda _: 'linux-fideduperange')

        self.assertEqual(result['relinked_files'], 1)
        self.assertEqual(result['reclaimed_bytes'], 16384)
        self.assertEqual(offsets, [(0, 0, 16384), (4096, 4096, 12288), (8192, 8192, 8192), (12288, 12288, 4096)])

    def test_macos_apfs_reports_duplicates_in_dry_run_and_refuses_inplace_apply(self):
        target_files = [
            self.wt1 / 'large.bin',
            self.wt1 / 'sub' / 'shared.dat',
            self.wt1 / 'node_modules' / 'pkg' / 'index.js',
        ]
        before = {p: (p.lstat().st_ino, p.lstat().st_mtime_ns, p.read_bytes()) for p in target_files}

        dry = reflink.dedupe([str(self.root)], apply=False, backend_detector=lambda _: 'apfs-no-atomic-inplace')
        self.assertEqual(dry['status'], 'ok')
        self.assertEqual(dry['backend'], 'apfs-no-atomic-inplace')
        self.assertFalse(dry['apply_supported'])
        self.assertEqual(dry['candidate_files'], 3)
        self.assertEqual(dry['reclaimable_bytes'], 8192 + 12288 + 16384)
        self.assertEqual(dry['relinked_files'], 0)
        self.assertEqual(dry['reclaimed_bytes'], 0)
        self.assertIn(reflink.APFS_DRY_RUN_NOTE, dry['notes'])
        self.assertNotIn('Rerun with --apply', reflink.render_text(dry))

        applied = reflink.dedupe([str(self.root)], apply=True, backend_detector=lambda _: 'apfs-no-atomic-inplace')
        self.assertEqual(applied['status'], 'unsupported')
        self.assertEqual(applied['backend'], 'apfs-no-atomic-inplace')
        self.assertFalse(applied['apply_supported'])
        self.assertEqual(applied['candidate_files'], 0)
        self.assertEqual(applied['relinked_files'], 0)
        self.assertEqual(applied['reclaimed_bytes'], 0)
        self.assertGreaterEqual(applied['skipped'].get('apfs_no_atomic_inplace', 0), 3)
        self.assertIn(reflink.APFS_APPLY_NOTE, applied['notes'])
        self.assertIn('Status: unsupported', reflink.render_text(applied))
        for p, expected in before.items():
            self.assertEqual((p.lstat().st_ino, p.lstat().st_mtime_ns, p.read_bytes()), expected)

        with self.assertRaises(reflink.UnsupportedReflinkError):
            reflink.reflink_replace(
                str(self.main / 'large.bin'),
                str(self.wt1 / 'large.bin'),
                (self.main / 'large.bin').lstat(),
                (self.wt1 / 'large.bin').lstat(),
                'apfs-no-atomic-inplace',
            )

    def test_detect_backend_identifies_apfs_as_no_atomic_inplace(self):
        with patch.object(reflink.sys, 'platform', 'darwin'), \
                patch.object(reflink, '_filesystem_types', return_value={'apfs'}):
            self.assertEqual(reflink.detect_backend(str(self.root)), 'apfs-no-atomic-inplace')
        with patch.object(reflink.sys, 'platform', 'darwin'), \
                patch.object(reflink, '_filesystem_types', return_value={'hfs'}):
            self.assertEqual(reflink.detect_backend(str(self.root)), 'unsupported')

    def test_linked_worktree_outside_roots_and_prefix_trap_are_strictly_skipped(self):
        allowed = self.root / 'allowed'
        allowed_prefix_trap = self.root / 'allowed-other'
        allowed.mkdir()
        allowed_prefix_trap.mkdir()

        main = allowed / 'app'
        main.mkdir()
        run_git(main, 'init', '-q', '-b', 'main')
        (main / 'blob.bin').write_bytes(b'M' * 8192)
        run_git(main, 'add', '.')
        run_git(main, 'commit', '-qm', 'init')

        wt_inside = allowed / 'app-wt-inside'
        wt_outside = allowed_prefix_trap / 'app-wt-outside'
        run_git(main, 'worktree', 'add', '-q', '-b', 'b-in', str(wt_inside))
        run_git(main, 'worktree', 'add', '-q', '-b', 'b-out', str(wt_outside))

        calls = []
        with patch.object(reflink, '_fideduperange_ioctl', side_effect=fake_fideduperange_same(calls)), \
                patch.object(reflink, 'extents_shared', return_value=False):
            dry = reflink.dedupe([str(allowed)], apply=False, backend_detector=lambda _: 'linux-fideduperange')
            applied = reflink.dedupe([str(allowed)], apply=True, backend_detector=lambda _: 'linux-fideduperange')

        for res in (dry, applied):
            self.assertEqual(res['skipped'].get('outside_roots'), 1)
            self.assertEqual(res['worktrees_scanned'], 2)
            self.assertEqual([item['target'] for item in res['candidates']], [str(wt_inside / 'blob.bin')])
        self.assertEqual(len(calls), 1)

    def test_protected_worktree_and_protected_subpath_are_strictly_skipped(self):
        protected_wt = self.root / 'protected-zone' / 'wt-protected'
        protected_wt.parent.mkdir()
        run_git(self.main, 'worktree', 'add', '-q', '-b', 'b-prot', str(protected_wt))

        (self.wt1 / 'keep_dir').mkdir()
        (self.wt1 / 'keep_dir' / '.keep-local').write_text('', encoding='utf-8')
        (self.wt1 / 'keep_dir' / 'secret.bin').write_bytes(b'S' * 8192)
        (self.main / 'keep_dir').mkdir()
        (self.main / 'keep_dir' / 'secret.bin').write_bytes(b'S' * 8192)
        run_git(self.main, 'add', 'keep_dir')
        run_git(self.main, 'commit', '-qm', 'add keep_dir')
        run_git(self.wt1, 'add', 'keep_dir/secret.bin')
        run_git(self.wt1, 'commit', '-qm', 'add keep_dir secret')

        calls = []
        with patch.object(reflink, '_fideduperange_ioctl', side_effect=fake_fideduperange_same(calls)), \
                patch.object(reflink, 'extents_shared', return_value=False):
            dry = reflink.dedupe(
                [str(self.root)],
                apply=False,
                protected=[str(protected_wt.parent), str(self.wt1 / 'sub')],
                backend_detector=lambda _: 'linux-fideduperange',
            )
            applied = reflink.dedupe(
                [str(self.root)],
                apply=True,
                protected=[str(protected_wt.parent), str(self.wt1 / 'sub')],
                backend_detector=lambda _: 'linux-fideduperange',
            )

        for res in (dry, applied):
            self.assertGreaterEqual(res['skipped'].get('protected', 0), 3)
            targets = {item['target'] for item in res['candidates']}
            self.assertFalse(any(t.startswith(str(protected_wt)) for t in targets))
            self.assertNotIn(str(self.wt1 / 'sub' / 'shared.dat'), targets)
            self.assertNotIn(str(self.wt1 / 'keep_dir' / 'secret.bin'), targets)
            self.assertIn(str(self.wt1 / 'large.bin'), targets)

    def test_symlinked_builtin_protected_folder_inside_scan_root_is_skipped(self):
        fake_home = self.root / 'fake-home'
        fake_home.mkdir()
        scan_root = self.root / 'scan-root'
        docs_target = scan_root / 'linked-docs'
        docs_target.mkdir(parents=True)
        (fake_home / 'Documents').symlink_to(docs_target)

        repo_main = docs_target / 'repo-main'
        repo_main.mkdir()
        run_git(repo_main, 'init', '-q', '-b', 'main')
        (repo_main / 'doc.bin').write_bytes(b'P' * 8192)
        run_git(repo_main, 'add', '.')
        run_git(repo_main, 'commit', '-qm', 'init')
        repo_wt = docs_target / 'repo-wt'
        run_git(repo_main, 'worktree', 'add', '-q', '-b', 'feat', str(repo_wt))

        calls = []
        with patch.dict(os.environ, {'HOME': str(fake_home)}), \
                patch.object(reflink, '_fideduperange_ioctl', side_effect=fake_fideduperange_same(calls)), \
                patch.object(reflink, 'extents_shared', return_value=False):
            dry = reflink.dedupe([str(scan_root)], apply=False, backend_detector=lambda _: 'linux-fideduperange')
            applied = reflink.dedupe([str(scan_root)], apply=True, backend_detector=lambda _: 'linux-fideduperange')

        for res in (dry, applied):
            self.assertEqual(res['candidate_files'], 0)
            self.assertEqual(res['relinked_files'], 0)
            self.assertEqual(res['worktrees_scanned'], 0)
            self.assertEqual(res['skipped'].get('protected'), 2)
        self.assertEqual(calls, [])

    def test_cli_positional_apply_enforces_rules_protected_and_symlink_protected(self):
        cfg_dir = self.root / 'cfg'
        cfg_dir.mkdir()
        prot_link = cfg_dir / 'protected-wt-link'
        prot_link.symlink_to(self.wt1)
        rules_path = cfg_dir / 'rules.toml'
        rules_path.write_text(
            f'alert_pct = 80\nworktree_idle_days = 7\narchive_idle_days = 4\n'
            f'nas_root = {json.dumps(str(cfg_dir / "nas"))}\n'
            f'report_dir = {json.dumps(str(cfg_dir / "reports"))}\n'
            'live = []\nalready_compressed_extensions = []\n'
            f'[hosts.local]\nkind = "posix"\nroots = []\n'
            f'protected = [{json.dumps(str(prot_link))}]\n',
            encoding='utf-8',
        )
        calls = []
        out = io.StringIO()
        with patch.object(reflink, 'detect_backend', return_value='linux-fideduperange'), \
                patch.object(reflink, '_fideduperange_ioctl', side_effect=fake_fideduperange_same(calls)), \
                patch.object(reflink, 'extents_shared', return_value=False), \
                patch('sys.stdout', out):
            code = cli.main(['reflink', '--rules', str(rules_path), '--apply', '--json', str(self.root)])
        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload['relinked_files'], 0)
        self.assertEqual(payload['skipped'].get('protected'), 1)
        self.assertEqual(calls, [])

        err_out = io.StringIO()
        with patch('sys.stdout', err_out):
            bad_code = cli.main(['reflink', '--rules', str(cfg_dir / 'missing.toml'), '--json', str(self.root)])
        self.assertEqual(bad_code, 2)
        self.assertEqual(json.loads(err_out.getvalue())['status'], 'incomplete')

        abbrev_out = io.StringIO()
        with patch('sys.stdout', abbrev_out):
            abbrev_code = cli.main(
                ['reflink', '--rul', str(cfg_dir / 'missing.toml'), '--apply', '--json', str(self.root)]
            )
        self.assertEqual(abbrev_code, 2)
        self.assertEqual(json.loads(abbrev_out.getvalue())['status'], 'incomplete')

    def test_active_and_malformed_lease_skip_worktree_while_expired_lease_proceeds(self):
        lease_file = self.wt1 / '.coldcleaner-lease'
        calls = []
        with patch.object(reflink, '_fideduperange_ioctl', side_effect=fake_fideduperange_same(calls)), \
                patch.object(reflink, 'extents_shared', return_value=False):
            lease_file.write_text('2099-01-01T00:00:00Z\n', encoding='utf-8')
            active_dry = reflink.dedupe([str(self.root)], apply=False, backend_detector=lambda _: 'linux-fideduperange')
            active_apply = reflink.dedupe([str(self.root)], apply=True, backend_detector=lambda _: 'linux-fideduperange')
            for res in (active_dry, active_apply):
                self.assertEqual(res['candidate_files'], 0)
                self.assertEqual(res['relinked_files'], 0)
                self.assertEqual(res['skipped'].get('leased'), 1)
            self.assertEqual(calls, [])

            lease_file.write_text('not-a-timestamp\n', encoding='utf-8')
            bad_apply = reflink.dedupe([str(self.root)], apply=True, backend_detector=lambda _: 'linux-fideduperange')
            self.assertEqual(bad_apply['relinked_files'], 0)
            self.assertEqual(bad_apply['skipped'].get('leased'), 1)
            self.assertEqual(calls, [])

            lease_file.write_text('2020-01-01T00:00:00Z\n', encoding='utf-8')
            sub_lease = self.wt1 / 'sub' / '.coldcleaner-lease'
            sub_lease.write_text('2099-01-01T00:00:00Z\n', encoding='utf-8')
            expired_wt_apply = reflink.dedupe([str(self.root)], apply=True,
                                              backend_detector=lambda _: 'linux-fideduperange')
            self.assertEqual(expired_wt_apply['relinked_files'], 2)
            targets = {item['target'] for item in expired_wt_apply['candidates']}
            self.assertIn(str(self.wt1 / 'large.bin'), targets)
            self.assertNotIn(str(self.wt1 / 'sub' / 'shared.dat'), targets)
            self.assertGreaterEqual(expired_wt_apply['skipped'].get('leased', 0), 1)

    def test_uppercase_ancestor_lease_and_late_lease_before_fideduperange_skip_cleanly(self):
        nested_parent = self.root / 'leased-parent'
        nested_parent.mkdir()
        wt_nested = nested_parent / 'repo-wt-nested'
        run_git(self.main, 'worktree', 'add', '-q', '-b', 'feat-nested', str(wt_nested))
        (nested_parent / '.COLDCLEANER-LEASE').write_text('2099-01-01T00:00:00Z\n', encoding='utf-8')

        calls = []
        with patch.object(reflink, '_fideduperange_ioctl', side_effect=fake_fideduperange_same(calls)), \
                patch.object(reflink, 'extents_shared', return_value=False):
            res = reflink.dedupe([str(self.root)], apply=False, backend_detector=lambda _: 'linux-fideduperange')
        self.assertEqual(res['skipped'].get('leased'), 1)
        self.assertFalse(any(str(wt_nested) in item['target'] for item in res['candidates']))

        (nested_parent / '.COLDCLEANER-LEASE').unlink()
        real_hash = reflink._hash_file
        created = []

        def create_late_lease_on_target_hash(path, expected_st):
            digest = real_hash(path, expected_st)
            if not created and Path(path).resolve() == (self.wt1 / 'large.bin').resolve():
                (self.wt1 / '.coldcleaner-lease').write_text('2099-01-01T00:00:00Z\n', encoding='utf-8')
                created.append(path)
            return digest

        late_inodes = []
        base_handler = fake_fideduperange_same([])

        def record_late_ioctl(src_fd, buf):
            dst_fd = struct.unpack_from('=q', buf, 24)[0]
            late_inodes.append(os.fstat(dst_fd).st_ino)
            base_handler(src_fd, buf)

        with patch.object(reflink, '_hash_file', side_effect=create_late_lease_on_target_hash), \
                patch.object(reflink, '_fideduperange_ioctl', side_effect=record_late_ioctl), \
                patch.object(reflink, 'extents_shared', return_value=False):
            late_res = reflink.dedupe([str(self.root)], apply=True, backend_detector=lambda _: 'linux-fideduperange')

        self.assertEqual(len(created), 1)
        self.assertGreaterEqual(late_res['skipped'].get('leased', 0), 1)
        self.assertFalse(any(Path(item['target']).resolve() == (self.wt1 / 'large.bin').resolve()
                             for item in late_res['candidates']))
        self.assertNotIn((self.wt1 / 'large.bin').lstat().st_ino, late_inodes)

    def test_unreadable_ancestor_fails_closed_for_lease_check(self):
        nested_parent = self.root / 'unreadable-parent'
        nested_parent.mkdir()
        wt_nested = nested_parent / 'repo-wt-hidden-lease'
        run_git(self.main, 'worktree', 'add', '-q', '-b', 'feat-hidden-lease', str(wt_nested))
        (nested_parent / '.COLDCLEANER-LEASE').write_text('2099-01-01T00:00:00Z\n', encoding='utf-8')

        real_listdir = os.listdir
        resolved_parent = os.path.realpath(nested_parent)

        def deny_parent_listdir(path):
            if os.path.realpath(path) == resolved_parent:
                raise PermissionError(errno.EACCES, 'Permission denied', path)
            return real_listdir(path)

        calls = []
        with patch.object(os, 'listdir', side_effect=deny_parent_listdir), \
                patch.object(reflink, '_fideduperange_ioctl', side_effect=fake_fideduperange_same(calls)), \
                patch.object(reflink, 'extents_shared', return_value=False):
            res = reflink.dedupe([str(self.root)], apply=True, backend_detector=lambda _: 'linux-fideduperange')

        self.assertEqual(res['skipped'].get('leased'), 1)
        self.assertFalse(any(str(wt_nested) in item['target'] for item in res['candidates']))

    def test_safety_guards_dirty_symlinks_nested_git_open_write_and_shared_inodes(self):
        (self.wt1 / 'same_size_diff.bin').write_bytes(b'B' * 6144)
        (self.main / 'untracked.bin').write_bytes(b'U' * 8192)
        (self.wt1 / 'untracked.bin').write_bytes(b'U' * 8192)
        (self.main / 'link.bin').symlink_to('large.bin')
        (self.wt1 / 'link.bin').symlink_to('large.bin')
        (self.wt1 / 'sub_link').symlink_to('sub')
        if hasattr(os, 'mkfifo'):
            os.mkfifo(self.wt1 / 'pipe.fifo')
        for wt in (self.main, self.wt1):
            nested = wt / 'nested_repo'
            nested.mkdir()
            (nested / '.git').write_text('gitdir: /dev/null\n', encoding='utf-8')
            (nested / 'payload.bin').write_bytes(b'N' * 8192)
        hl_main = self.main / 'hardlinked.bin'
        hl_wt1 = self.wt1 / 'hardlinked.bin'
        hl_main.write_bytes(b'H' * 8192)
        os.link(hl_main, hl_wt1)
        run_git(self.main, 'add', 'hardlinked.bin')
        run_git(self.main, 'commit', '-qm', 'add hardlinked')
        hl_wt1.unlink()
        run_git(self.wt1, 'merge', '-q', 'main', '-m', 'merge hardlinked')
        hl_wt1.unlink()
        os.link(hl_main, hl_wt1)

        large_st = (self.wt1 / 'large.bin').lstat()
        open_writes = {(large_st.st_dev, large_st.st_ino)}

        def fake_extents(path_a, st_a, path_b, st_b, backend):
            if st_a.st_dev == st_b.st_dev and st_a.st_ino == st_b.st_ino:
                return True
            return os.path.basename(path_b) == 'shared.dat'

        with patch.object(reflink, '_open_write_inodes', return_value=open_writes), \
                patch.object(reflink, 'extents_shared', side_effect=fake_extents):
            result = reflink.dedupe([str(self.root)], apply=False, backend_detector=lambda _: 'linux-fideduperange')

        self.assertEqual(result['status'], 'ok')
        self.assertEqual([item['target'] for item in result['candidates']],
                         [str(self.wt1 / 'node_modules' / 'pkg' / 'index.js')])
        self.assertGreaterEqual(result['skipped']['dirty'], 2)
        self.assertGreaterEqual(result['skipped']['symlink'], 3)
        if hasattr(os, 'mkfifo'):
            self.assertEqual(result['skipped']['special_file'], 1)
        self.assertGreaterEqual(result['skipped']['nested_git_repo'], 2)
        self.assertEqual(result['skipped']['open_for_write'], 1)
        self.assertEqual(result['skipped']['already_shared'], 2)
        self.assertGreaterEqual(result['skipped']['git_metadata'], 2)

    def test_cross_device_files_are_skipped(self):
        real_scan = reflink._scan_worktree

        class FakeStat:
            def __init__(self, st, dev):
                self._st = st
                self.st_dev = dev

            def __getattr__(self, name):
                return getattr(self._st, name)

        def scan_with_cross_dev(worktree, dirty, open_writes, min_bytes, skipped, by_rel, protected_roots):
            temp = {}
            real_scan(worktree, dirty, open_writes, min_bytes, skipped, temp, protected_roots)
            dev_override = 1001 if Path(worktree).resolve() == self.main.resolve() else 2002
            for rel, items in temp.items():
                for path, st, wt in items:
                    by_rel.setdefault(rel, []).append((path, FakeStat(st, dev_override), wt))

        with patch.object(reflink, '_scan_worktree', side_effect=scan_with_cross_dev):
            result = reflink.dedupe([str(self.root)], apply=False, backend_detector=lambda _: 'linux-fideduperange')

        self.assertEqual(result['candidate_files'], 0)
        self.assertEqual(result['reclaimable_bytes'], 0)
        self.assertGreaterEqual(result['skipped']['cross_device'], 3)

    def test_non_cow_filesystem_returns_clean_unsupported_without_partial_edits(self):
        large = self.wt1 / 'large.bin'
        before = (large.lstat().st_ino, large.read_bytes())

        result = reflink.dedupe([str(self.root)], apply=True, backend_detector=lambda _: 'unsupported')
        self.assertEqual(result['status'], 'unsupported')
        self.assertEqual(result['backend'], 'unsupported')
        self.assertFalse(result['apply_supported'])
        self.assertEqual(result['relinked_files'], 0)
        self.assertEqual(result['reclaimed_bytes'], 0)
        self.assertEqual((large.lstat().st_ino, large.read_bytes()), before)

        def fail_enotsup(src_fd, buf):
            raise OSError(errno.EOPNOTSUPP, os.strerror(errno.EOPNOTSUPP))

        with patch.object(reflink, '_fideduperange_ioctl', side_effect=fail_enotsup), \
                patch.object(reflink, 'extents_shared', return_value=False):
            result2 = reflink.dedupe([str(self.root)], apply=True, backend_detector=lambda _: 'linux-fideduperange')

        self.assertEqual(result2['status'], 'unsupported')
        self.assertEqual(result2['backend'], 'unsupported')
        self.assertFalse(result2['apply_supported'])
        self.assertEqual(result2['relinked_files'], 0)
        self.assertEqual(result2['reclaimed_bytes'], 0)
        self.assertEqual(result2['errors'], [])
        self.assertEqual((large.lstat().st_ino, large.read_bytes()), before)

    def test_real_filesystem_behavior_without_mocks(self):
        backend = reflink.detect_backend(str(self.root))
        self.assertIn(backend, ('linux-fideduperange', 'apfs-no-atomic-inplace', 'unsupported'))

        dry = reflink.dedupe([str(self.root)], apply=False)
        applied = reflink.dedupe([str(self.root)], apply=True)

        if backend == 'unsupported':
            self.assertEqual(dry['status'], 'unsupported')
            self.assertEqual(dry['backend'], 'unsupported')
            self.assertEqual(applied['status'], 'unsupported')
            self.assertEqual(applied['backend'], 'unsupported')
            self.assertEqual(applied['relinked_files'], 0)
            self.assertEqual(applied['reclaimed_bytes'], 0)
        elif backend == 'linux-fideduperange':
            self.assertEqual(dry['status'], 'ok')
            self.assertEqual(dry['candidate_files'], 3)
            self.assertEqual(applied['status'], 'ok')
            self.assertEqual(applied['relinked_files'], 3)
            self.assertEqual(applied['reclaimed_bytes'], 8192 + 12288 + 16384)
            self.assertEqual((self.wt1 / 'large.bin').read_bytes(), b'A' * 8192)
            self.assertEqual(stat.S_IMODE((self.wt1 / 'large.bin').lstat().st_mode), 0o755)
            second = reflink.dedupe([str(self.root)], apply=False)
            self.assertEqual(second['candidate_files'], 0)
            self.assertEqual(second['skipped'].get('already_shared'), 3)
        else:
            self.assertEqual(dry['status'], 'ok')
            self.assertEqual(dry['backend'], 'apfs-no-atomic-inplace')
            self.assertFalse(dry['apply_supported'])
            self.assertEqual(applied['status'], 'unsupported')
            self.assertEqual(applied['relinked_files'], 0)

    def test_cli_json_and_text_with_positional_path_and_rules_host(self):
        res = subprocess.run(
            [sys.executable, '-B', '-m', 'coldcleaner', 'reflink', str(self.root), '--json'],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        payload = json.loads(res.stdout)
        self.assertEqual(payload['schema_version'], 1)
        self.assertIn(payload['status'], ('ok', 'unsupported'))
        self.assertEqual(payload['mode'], 'dry-run')
        self.assertIn(payload['backend'], ('linux-fideduperange', 'apfs-no-atomic-inplace', 'unsupported'))
        self.assertIsInstance(payload['apply_supported'], bool)

        text_res = subprocess.run(
            [sys.executable, '-B', '-m', 'coldcleaner', 'reflink', str(self.root)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(text_res.returncode, 0, text_res.stderr)
        self.assertIn('Mode: dry-run', text_res.stdout)

        bad = subprocess.run(
            [sys.executable, '-B', '-m', 'coldcleaner', 'reflink', str(self.root), '--host', 'local', '--json'],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(json.loads(bad.stdout)['status'], 'incomplete')

        cfg_dir = self.root / 'cfg'
        cfg_dir.mkdir()
        rules_path = cfg_dir / 'rules.toml'
        rules_path.write_text(
            f'alert_pct = 80\nworktree_idle_days = 7\narchive_idle_days = 4\n'
            f'nas_root = {json.dumps(str(cfg_dir / "nas"))}\n'
            f'report_dir = {json.dumps(str(cfg_dir / "reports"))}\n'
            'live = []\nalready_compressed_extensions = []\n'
            f'[hosts.local]\nkind = "posix"\nroots = [{json.dumps(str(self.main))}]\n'
            f'protected = [{json.dumps(str(self.wt1))}]\n'
            '[hosts.win]\nkind = "powershell"\nssh = "win.example.invalid"\nroots = []\n',
            encoding='utf-8',
        )
        local_res = subprocess.run(
            [sys.executable, '-B', '-m', 'coldcleaner', 'reflink', '--rules', str(rules_path),
             '--host', 'local', '--json'],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(local_res.returncode, 0, local_res.stdout + local_res.stderr)
        local_payload = json.loads(local_res.stdout)
        self.assertEqual(local_payload['schema_version'], 1)
        self.assertEqual(local_payload['host'], 'local')
        self.assertEqual(local_payload['skipped'].get('outside_roots'), 1)

        win_res = subprocess.run(
            [sys.executable, '-B', '-m', 'coldcleaner', 'reflink', '--rules', str(rules_path),
             '--host', 'win', '--json'],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(win_res.returncode, 0, win_res.stdout + win_res.stderr)
        win_payload = json.loads(win_res.stdout)
        self.assertEqual(win_payload['status'], 'unsupported')
        self.assertEqual(win_payload['backend'], 'unsupported')
        self.assertFalse(win_payload['apply_supported'])

        min_res = reflink.dedupe([str(self.root)], apply=False, min_bytes=16384,
                                 backend_detector=lambda _: 'linux-fideduperange')
        self.assertEqual(min_res['candidate_files'], 1)
        self.assertEqual(min_res['reclaimable_bytes'], 16384)
        self.assertEqual(min_res['candidates'][0]['target'], str(self.wt1 / 'node_modules' / 'pkg' / 'index.js'))

    def test_remote_posix_host_executes_through_hosts_python_run_with_protected(self):
        remote = hosts.Host('remote-mac', 'posix', ssh='mac.example.invalid')
        fake_stdout = json.dumps(dict(
            status='ok', mode='dry-run', backend='apfs-no-atomic-inplace', apply_supported=False,
            min_bytes=4096, worktree_groups=1, worktrees_scanned=2, candidate_files=1, relinked_files=0,
            reclaimable_bytes=8192, reclaimed_bytes=0, skipped={}, candidates=[], notes=[], errors=[],
        )).encode('utf-8')
        fake_proc = subprocess.CompletedProcess(['ssh'], 0, stdout=fake_stdout, stderr=b'')
        with patch.object(hosts, 'python_run', return_value=fake_proc) as mocked:
            res = reflink.run_host(remote, ['~/projects'], apply=False, min_bytes=4096, protected=['/srv/keep'])
        self.assertEqual(res['backend'], 'apfs-no-atomic-inplace')
        self.assertFalse(res['apply_supported'])
        self.assertEqual(res['reclaimable_bytes'], 8192)
        mocked.assert_called_once()
        call_args = mocked.call_args
        self.assertEqual(call_args.args[0], remote)
        self.assertEqual(call_args.args[2], {
            'roots': ['~/projects'],
            'apply': False,
            'min_bytes': 4096,
            'protected': ['/srv/keep'],
        })

    def test_run_hosts_forwards_configured_protected_paths(self):
        local = hosts.Host('local', 'posix')
        config = {
            'hosts': {
                'local': {
                    'roots': [str(self.root)],
                    'protected': [str(self.wt1)],
                },
            },
        }
        with patch.object(reflink, 'detect_backend', return_value='linux-fideduperange'):
            res = reflink.run_hosts(config, [local], apply=False)
        self.assertEqual(res['host'], 'local')
        self.assertEqual(res['candidate_files'], 0)
        self.assertEqual(res['skipped'].get('protected'), 1)

    def test_reflink_module_hashes_without_file_digest(self):
        sample = self.root / 'sample.bin'
        data = b'sample\x00\xff' * 1024
        sample.write_bytes(data)
        st = sample.lstat()
        with patch.object(hashlib, 'file_digest', create=True, side_effect=AssertionError('must not use file_digest')):
            digest = reflink._hash_file(str(sample), st)
        self.assertEqual(digest, hashlib.sha256(data).hexdigest())

    def test_fiemap_extent_equality_and_inline_guard(self):
        def fake_ioctl_builder(extents):
            def fake_ioctl(fd, op, buf, mutate):
                self.assertEqual(op, reflink.FS_IOC_FIEMAP)
                struct.pack_into('=QQIIII', buf, 0, 0, reflink.FIEMAP_MAX_OFFSET, 0, len(extents), reflink.FIEMAP_BATCH, 0)
                for index, (logical, physical, length, flags) in enumerate(extents):
                    struct.pack_into('=QQQQQIIII', buf, 32 + index * 56, logical, physical, length, 0, 0, flags, 0, 0, 0)
                return 0
            return fake_ioctl

        a = self.main / 'large.bin'
        b = self.wt1 / 'large.bin'
        st_a, st_b = a.lstat(), b.lstat()
        shared_extent = [(0, 409600, 8192, reflink.FIEMAP_EXTENT_LAST | 0x2000)]
        with patch.object(reflink.sys, 'platform', 'linux'), \
                patch.object(reflink, 'fcntl', SimpleNamespace(ioctl=fake_ioctl_builder(shared_extent))):
            self.assertTrue(reflink.extents_shared(str(a), st_a, str(b), st_b, 'linux-fideduperange'))

        inline_extent = [(0, 409600, 8192, reflink.FIEMAP_EXTENT_LAST | reflink.FIEMAP_EXTENT_DATA_INLINE)]
        with patch.object(reflink.sys, 'platform', 'linux'), \
                patch.object(reflink, 'fcntl', SimpleNamespace(ioctl=fake_ioctl_builder(inline_extent))):
            self.assertFalse(reflink.extents_shared(str(a), st_a, str(b), st_b, 'linux-fideduperange'))

    def test_reflink_cli_help_lists_summary_and_flags(self):
        out = io.StringIO()
        with patch('sys.stdout', out), self.assertRaises(SystemExit) as ctx:
            cli.parser().parse_args(['reflink', '--help'])
        self.assertEqual(ctx.exception.code, 0)
        text = out.getvalue()
        for label in ('--rules RULES', '--host HOST', '--local', '--apply', '--json', '--min-bytes MIN_BYTES'):
            self.assertIn(label, text)


if __name__ == '__main__':
    unittest.main()
