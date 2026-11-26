import contextlib
import io
import json
import shutil
import stat
import os
import subprocess
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from coldcleaner import cli, hosts, protect, reclaim, reclaim_probe, store, triage
from tests import outside_git
from tests import test_reclaim

outside_git.use()

GITHUB_ORIGIN = 'https://github.com/example/repo.git'
OLD = time.time() - 30 * 86400
BIG = b'x' * 50000
LAYOUTS = {
    'node_modules': {'.package-lock.json': b'{}', 'pkg/package.json': b'{}', 'pkg/index.js': BIG},
    'target': {'CACHEDIR.TAG': b'Signature: 8a477f597d28d172789f06886806bc55', 'debug/app': BIG},
    '.venv': {'pyvenv.cfg': b'home = /usr/bin', 'lib/python3.12/site-packages/mod.py': BIG},
    '.pytest_cache': {'CACHEDIR.TAG': b'', 'README.md': b'', 'v/cache/lastfailed': BIG},
    '.mypy_cache': {'CACHEDIR.TAG': b'', '.gitignore': b'*', '3.12/mod.data.json': BIG,
                    '3.12/cache.db': b'SQLite format 3\x00' + bytes(84), '3.12/cache.db-wal': b''},
}


def missing_gh(args, **kwargs):
    if args[0] == 'gh':
        raise subprocess.CalledProcessError(127, args, b'', b'gh: command not found')
    raise AssertionError(f'unexpected controller call {args}')


def age(root):
    for base, dirs, files in os.walk(root):
        for name in dirs + files:
            os.utime(os.path.join(base, name), (OLD, OLD), follow_symlinks=False)
    os.utime(root, (OLD, OLD))


class Fixture(unittest.TestCase):
    setUp = test_reclaim.ReclaimTests.setUp
    git = test_reclaim.ReclaimTests.git

    def repo(self, default='main'):
        repo = self.root / 'repo'; remote = self.root / 'remote.git'
        repo.mkdir()
        self.git(repo, 'init', '-b', default)
        for key, value in (('user.name', 'Test'), ('user.email', 'test@localhost'), ('commit.gpgsign', 'false')):
            self.git(repo, 'config', key, value)
        (repo / 'tracked').write_text('durable')
        (repo / '.gitignore').write_text('node_modules/\ntarget/\n.venv/\n.pytest_cache/\n')
        self.git(repo, 'add', '.')
        self.git(repo, 'commit', '-m', 'initial')
        self.git(self.root, 'init', '--bare', '-b', default, str(remote))
        self.git(repo, 'remote', 'add', 'origin', GITHUB_ORIGIN)
        self.git(repo, 'push', str(remote), default)
        self.config['hosts']['test']['roots'] = [str(self.root)]
        self.engine.origin_listing = lambda repo_name, fresh=False: self.git(self.root, 'ls-remote', str(remote))
        return repo, remote


class LocalProofTests(Fixture):
    def worktree(self, default='main', merged=True):
        repo, remote = self.repo(default)
        work = self.root / 'work'
        self.git(repo, 'worktree', 'add', '-b', 'done', str(work))
        if not merged:
            (work / 'feature').write_text('unmerged')
            self.git(work, 'add', 'feature')
            self.git(work, 'commit', '-m', 'feature')
        self.git(work, 'push', str(remote), 'done')
        return repo, work

    def run_worktrees(self, apply=True):
        self.engine.apply = apply
        with patch.object(hosts, 'controller', side_effect=missing_gh) as controller, \
             patch.object(protect, 'collect', return_value=self.protection):
            self.engine.worktrees()
        return controller

    def row(self, work):
        return next(row for row in self.entry.actions if row['path'] == str(work))

    def test_missing_gh_removes_merged_worktree_by_local_ancestry(self):
        repo, work = self.worktree()
        self.run_worktrees()
        self.assertFalse(work.exists(), self.entry.actions)
        row = self.row(work)
        self.assertEqual((row['action'], row['merged'], row['pull_requests']), ('remove worktree and local branch', True, []))
        self.assertTrue(any('GitHub CLI gh not found' in note for note in self.entry.notes), self.entry.notes)

    def test_missing_gh_holds_unmerged_published_worktree(self):
        repo, work = self.worktree(merged=False)
        self.run_worktrees()
        self.assertTrue(work.exists())
        self.assertEqual((self.row(work)['action'], self.row(work)['reason']),
                         ('skip', 'IN USE: work is neither merged nor closed at this head'))

    def test_missing_gh_holds_unpushed_commit(self):
        repo, work = self.worktree()
        (work / 'local').write_text('unpushed')
        self.git(work, 'add', 'local')
        self.git(work, 'commit', '-m', 'unpushed')
        self.run_worktrees()
        self.assertTrue(work.exists())
        self.assertTrue(self.row(work)['reason'].startswith('UNIQUE: unpushed commits'), self.row(work))

    def test_missing_gh_holds_dirty_and_untracked_worktrees(self):
        for change in ('tracked', 'untracked'):
            with self.subTest(change=change):
                self.tearDown_all()
                repo, work = self.worktree()
                (work / change).write_text('edited')
                self.run_worktrees()
                self.assertTrue(work.exists())
                self.assertEqual(self.row(work)['reason'], 'IN USE: uncommitted work or stashes')

    def tearDown_all(self):
        self.doCleanups()
        self.setUp()

    def test_missing_gh_holds_worktree_with_git_lock(self):
        repo, work = self.worktree()
        admin = Path(self.git(work, 'rev-parse', '--path-format=absolute', '--git-dir'))
        (admin / 'index.lock').write_text('')
        self.run_worktrees()
        self.assertTrue(work.exists())
        self.assertIn('Git transaction lock', self.row(work)['reason'])

    def test_missing_gh_holds_worktree_used_by_a_process(self):
        repo, work = self.worktree()
        with patch.object(reclaim_probe, 'references', return_value=[str(work / 'tracked')]):
            self.run_worktrees()
        self.assertTrue(work.exists())
        self.assertIn('running process uses', self.row(work)['reason'])

    def test_no_gh_flag_never_calls_gh(self):
        self.config['no_gh'] = True
        self.engine = reclaim.Reclaimer(self.host, self.config, True, self.protection, self.entry)
        repo, work = self.worktree()
        controller = self.run_worktrees()
        self.assertFalse(work.exists(), self.entry.actions)
        self.assertFalse([call for call in controller.call_args_list if call.args[0][0] == 'gh'])
        self.assertTrue(any('(--no-gh)' in note for note in self.entry.notes))

    def test_missing_gh_uses_remote_default_branch_without_main(self):
        repo, work = self.worktree(default='trunk')
        self.run_worktrees()
        self.assertFalse(work.exists(), self.entry.actions)

    def test_missing_gh_ignores_main_when_remote_default_branch_is_trunk(self):
        repo, work = self.worktree(default='trunk', merged=False)
        self.git(work, 'push', str(self.root / 'remote.git'), 'done:refs/heads/main')
        self.run_worktrees()
        self.assertTrue(work.exists())
        self.assertEqual(self.row(work)['reason'], 'IN USE: work is neither merged nor closed at this head')

    def test_missing_gh_holds_detached_worktree_at_merged_commit(self):
        repo, work = self.worktree()
        self.git(work, 'checkout', '--detach')
        self.run_worktrees()
        self.assertTrue(work.exists())
        self.assertEqual(self.row(work)['reason'], 'IN USE: work is neither merged nor closed at this head')

    def test_default_branch_needs_remote_head_or_one_unambiguous_branch(self):
        for refs, expected in (({'HEAD': 't', 'refs/heads/main': 'm'}, 't'), ({'refs/heads/main': 'm'}, 'm'),
                               ({'refs/heads/master': 'r'}, 'r'), ({'refs/heads/main': 'm', 'refs/heads/master': 'r'}, None), ({}, None)):
            self.assertEqual(reclaim_probe.default_branch(refs), expected, refs)

    def test_missing_gh_never_selects_abandoned_work(self):
        repo, work = self.worktree(merged=False)
        self.config['abandoned_idle_days'] = 0
        self.run_worktrees(apply=False)
        self.assertNotEqual(self.row(work)['action'], 'would archive abandoned worktree')

    def test_missing_gh_is_reported_without_retry_delay(self):
        started = time.monotonic()
        with patch.object(hosts, 'controller', side_effect=missing_gh):
            with self.assertRaises(reclaim.GitHubUnavailable):
                reclaim.pull_requests('example/repo', 'done', 'a' * 40)
        self.assertLess(time.monotonic() - started, 1)


class AgentRootTests(unittest.TestCase):
    def test_agent_worktree_roots(self):
        home = Path('/h')
        with patch.object(Path, 'home', return_value=home):
            for path in ('/h/.codex/worktrees/a1/repo', '/h/.t3/worktrees/repo/branch', '/h/.cursor/worktrees/repo/abc',
                         '/h/conductor/workspaces/repo/name', '/h/projects/repo/.claude/worktrees/task',
                         '/h/projects/repo/.worktrees/branch'):
                self.assertTrue(reclaim_probe.agent_path(path), path)
            for path in ('/h/projects/repo', '/h/.claude/projects/x', '/h/projects/repo/.claude/worktrees',
                         '/elsewhere/.codex/worktrees/a/b'):
                self.assertFalse(reclaim_probe.agent_path(path), path)


class RebuildTests(Fixture):
    def setUp(self):
        super().setUp()
        self.config['live'] = ['worktree', 'archive', 'rebuild']
        self.config['worktree_idle_days'] = 1
        self.checkout, _ = self.repo()

    def cache(self, name='node_modules', files=('package.json', 'package-lock.json')):
        for item in files:
            (self.checkout / item).write_text('{}')
        folder = self.checkout / name
        for relative, data in LAYOUTS[name].items():
            (folder / relative).parent.mkdir(parents=True, exist_ok=True)
            (folder / relative).write_bytes(data)
        return folder

    def idle(self):
        age(self.checkout)
        admin = Path(self.git(self.checkout, 'rev-parse', '--path-format=absolute', '--git-dir'))
        for item in ('HEAD', 'index', 'logs/HEAD'):
            os.utime(admin / item, (OLD, OLD))

    def scan(self, apply=False):
        self.engine.apply = apply
        with patch.object(protect, 'collect', return_value=self.protection), \
             patch.object(store, 'archive', side_effect=AssertionError('rebuildable caches are never archived')):
            self.engine.rebuilds()
        return [row for row in self.entry.actions if row['tier'] == 'rebuild']

    def approve_all(self):
        rows = self.scan()
        plan = Path(self.config['report_dir']) / 'plan.json'
        plan.parent.mkdir(parents=True, exist_ok=True)
        reclaim.write_plan(plan, [self.entry], self.config.get('rules_sha256'))
        reclaim.approve(self.config['report_dir'], plan, ['all'])
        self.entry.actions.clear()
        return rows

    def test_idle_proven_cache_is_planned_then_deleted_without_nas_copy_after_approval(self):
        folder = self.cache()
        self.idle()
        rows = self.approve_all()
        self.assertEqual([(row['action'], row['approval']) for row in rows], [('would delete rebuildable cache', True)])
        self.assertIn('package.json, package-lock.json', rows[0]['reason'])
        before = rows[0]['bytes']
        self.assertGreater(before, 50000)
        done = self.scan(apply=True)
        self.assertFalse(folder.exists())
        self.assertTrue((self.checkout / 'package.json').exists() and (self.checkout / 'tracked').exists())
        self.assertEqual([(row['action'], row['bytes']) for row in done], [('delete rebuildable cache', before)])
        self.assertFalse((self.root / 'nas').exists())
        self.assertEqual(json.loads((Path(self.config['report_dir']) / 'approvals.json').read_text()), {})

    def test_apply_without_approval_keeps_cache(self):
        folder = self.cache()
        self.idle()
        rows = self.scan(apply=True)
        self.assertTrue(folder.exists())
        self.assertEqual(rows[0]['reason'], reclaim.APPROVAL_NEEDED)

    def test_changed_cache_after_approval_is_stale(self):
        folder = self.cache()
        self.idle()
        self.approve_all()
        (folder / 'pkg' / 'new.js').write_text('x')
        self.idle()
        rows = self.scan(apply=True)
        self.assertTrue(folder.exists())
        self.assertEqual(rows[0]['reason'], reclaim.APPROVAL_STALE)

    def test_cache_without_manifest_proof_is_not_a_candidate(self):
        for name, files in (('node_modules', ('package.json',)), ('node_modules', ()), ('target', ()), ('.venv', ())):
            with self.subTest(name=name, files=files):
                folder = self.cache(name, files)
                self.idle()
                self.assertEqual(self.scan(), [])
                self.assertTrue(folder.exists())
                for item in files:
                    (self.checkout / item).unlink()
                shutil.rmtree(folder)

    def test_rust_and_python_caches_with_manifests_are_candidates(self):
        self.cache('target', ('Cargo.toml',))
        self.cache('.pytest_cache', ('pyproject.toml',))
        self.cache('.mypy_cache')
        self.cache('.venv')
        self.idle()
        self.assertEqual(sorted(Path(row['path']).name for row in self.scan()), ['.mypy_cache', '.pytest_cache', '.venv', 'target'])

    def test_unrecognized_files_or_missing_tool_marker_hold_the_cache(self):
        cases = (('target', ('Cargo.toml',), 'notes.txt'), ('node_modules', ('package.json', 'package-lock.json'), 'important.txt'),
                 ('.venv', ('pyproject.toml',), 'data.csv'), ('.pytest_cache', ('pyproject.toml',), 'keep.txt'),
                 ('node_modules', ('package.json', 'package-lock.json'), '.personal-notes'),
                 ('target', ('Cargo.toml',), 'flycheck-notes.txt'), ('.venv', ('pyproject.toml',), 'lib/personal-notes.txt'),
                 ('.venv', ('pyproject.toml',), 'lib/python3.12/personal-notes.txt'),
                 ('.pytest_cache', ('pyproject.toml',), 'v/personal-notes.txt'),
                 ('.mypy_cache', ('pyproject.toml',), '3.12/personal-notes.txt'),
                 ('.mypy_cache', ('pyproject.toml',), '3.12/personal-notes.db'),
                 ('.mypy_cache', ('pyproject.toml',), '3.12/cache.db'),
                 ('target', ('Cargo.toml',), None), ('node_modules', ('package.json', 'package-lock.json'), None),
                 ('.venv', ('pyproject.toml',), None))
        markers = {'target': 'CACHEDIR.TAG', 'node_modules': '.package-lock.json', '.venv': 'pyvenv.cfg'}
        for name, files, user_file in cases:
            with self.subTest(name=name, user_file=user_file):
                folder = self.cache(name, files)
                if user_file:
                    (folder / user_file).parent.mkdir(parents=True, exist_ok=True)
                    (folder / user_file).write_text('only copy')
                else:
                    (folder / markers[name]).unlink()
                self.idle()
                self.assertEqual(self.scan(apply=True), [])
                self.assertTrue(folder.exists())
                if user_file:
                    self.assertEqual((folder / user_file).read_text(), 'only copy')
                shutil.rmtree(folder)

    def test_fifo_named_like_mypy_sqlite_cache_holds_without_blocking(self):
        folder = self.cache('.mypy_cache', ('pyproject.toml',))
        (folder / '3.12/cache.db').unlink()
        os.mkfifo(folder / '3.12/cache.db')
        self.idle()
        self.assertEqual(self.scan(apply=True), [])
        self.assertTrue(stat.S_ISFIFO((folder / '3.12/cache.db').lstat().st_mode))

    def test_cache_replaced_after_its_final_check_is_not_deleted(self):
        folder = self.cache()
        self.idle()
        self.approve_all()
        aside = self.root / 'aside'
        original = reclaim_probe.guard
        calls = []

        def replace_after_second_guard(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(args[0])
            if len(calls) == 2:
                folder.rename(aside)
                (folder / 'pkg').mkdir(parents=True)
                (folder / 'pkg' / 'package.json').write_text('{}')
                (folder / 'mine.txt').write_text('replacement')
            return result

        with patch.object(reclaim_probe, 'guard', side_effect=replace_after_second_guard):
            rows = self.scan(apply=True)
        self.assertEqual(len(calls), 2)
        self.assertEqual(rows[0]['reason'], reclaim.APPROVAL_STALE)
        self.assertEqual((folder / 'mine.txt').read_text(), 'replacement')
        self.assertEqual((aside / 'pkg' / 'index.js').read_bytes(), BIG)
        self.assertEqual([item.name for item in self.checkout.iterdir() if 'coldcleaner-removing' in item.name], [])

    def test_cache_modified_in_place_after_its_final_check_is_not_deleted(self):
        folder = self.cache()
        self.idle()
        self.approve_all()
        original = reclaim_probe.guard
        calls = []

        def write_after_second_guard(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(args[0])
            if len(calls) == 2:
                (folder / 'pkg' / 'late.js').write_text('late')
            return result

        with patch.object(reclaim_probe, 'guard', side_effect=write_after_second_guard):
            rows = self.scan(apply=True)
        self.assertEqual(rows[0]['reason'], reclaim.APPROVAL_STALE)
        self.assertEqual((folder / 'pkg' / 'late.js').read_text(), 'late')

    def test_tracked_cache_is_not_a_candidate(self):
        (self.checkout / '.gitignore').write_text('')
        folder = self.cache()
        self.git(self.checkout, 'add', '.')
        self.git(self.checkout, 'commit', '-m', 'vendor')
        self.idle()
        self.assertEqual(self.scan(), [])

    def test_symlinked_cache_is_not_a_candidate(self):
        outside = self.root / 'outside'
        (outside / 'pkg').mkdir(parents=True)
        for item in ('package.json', 'package-lock.json'):
            (self.checkout / item).write_text('{}')
        (self.checkout / 'node_modules').symlink_to(outside)
        self.idle()
        self.assertEqual(self.scan(), [])
        self.assertTrue((outside / 'pkg').exists())

    def test_link_escaping_the_cache_is_refused(self):
        folder = self.cache('.venv', ('pyproject.toml',))
        (folder / 'bin').mkdir()
        (folder / 'bin' / 'python').symlink_to('/usr/bin/python3')
        self.idle()
        rows = self.scan()
        self.assertEqual(rows[0]['action'], 'skip')
        self.assertIn('symlink escapes', rows[0]['reason'])

    def test_recent_cache_is_held(self):
        folder = self.cache()
        self.idle()
        os.utime(folder / 'pkg' / 'index.js')
        rows = self.scan()
        self.assertEqual((rows[0]['action'], rows[0]['reason']), ('skip', 'recent activity within 1 days'))

    def test_recent_git_activity_in_checkout_holds_its_caches(self):
        self.cache()
        self.idle()
        admin = Path(self.git(self.checkout, 'rev-parse', '--path-format=absolute', '--git-dir'))
        os.utime(admin / 'index')
        rows = self.scan()
        self.assertEqual(rows[0]['reason'], 'recent Git activity in checkout within 1 days')

    def test_process_in_checkout_holds_its_caches(self):
        folder = self.cache()
        self.idle()
        with patch.object(reclaim_probe, 'references', return_value=[str(self.checkout / 'tracked')]):
            rows = self.scan()
        self.assertIn('running process uses', rows[0]['reason'])
        self.assertTrue(folder.exists())

    def test_pass_runs_only_when_rebuild_is_live(self):
        for live, expected in ((['worktree', 'archive'], []), (['worktree', 'archive', 'rebuild'], ['rebuilds'])):
            with self.subTest(live=live):
                self.config['live'] = live
                self.protection.paths = []
                called = []
                steps = {name: lambda self, name=name: called.append(name)
                         for name in ('worktrees', 'clones', 'rebuilds', 'archives', 'unlisted')}
                with patch.object(cli.disk, 'measure', return_value=cli.disk.Usage(100, 10, 10.0)), \
                     patch.object(protect, 'collect', return_value=self.protection), \
                     patch.multiple(reclaim.Reclaimer, **steps), contextlib.redirect_stdout(io.StringIO()):
                    cli.run(self.config, [self.host])
                self.assertEqual([name for name in called if name == 'rebuilds'], expected)

    def test_triage_shows_reclaimable_totals(self):
        self.cache()
        self.idle()
        rows = self.scan()
        plan = Path(self.config['report_dir']) / '2026-01-01-000000-000000-00000000-0000-0000-0000-000000000000.md.plan.json'
        with patch.object(triage, 'plan_items', return_value=[dict(row, host='test', plan=plan) for row in rows]):
            lines = triage.rebuildable(self.config, {'test'})
        self.assertTrue(lines[0].startswith('Rebuildable caches awaiting approval: 1 ('), lines)
        self.assertIn(rows[0]['id'], lines[1])


if __name__ == '__main__':
    unittest.main()
