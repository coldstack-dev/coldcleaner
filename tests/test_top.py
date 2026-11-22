import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from coldcleaner import fleet, reclaim, report, rules


class TopTests(unittest.TestCase):
    def test_ranks_candidates_without_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / 'rules.toml'
            reports = root / 'reports'
            config.write_text(
                f'alert_pct = 80\nworktree_idle_days = 7\narchive_idle_days = 4\n'
                f'nas_root = {json.dumps(str(root / "nas"))}\nreport_dir = {json.dumps(str(reports))}\n'
                'live = ["worktree", "archive"]\nalready_compressed_extensions = []\n[hosts.example]\nkind = "posix"\n'
            )
            sha = rules.load(config)['rules_sha256']
            entry = report.HostReport('example')
            scratch = '/srv/example/projects/a/.scratch'
            modules = '/srv/example/projects/b/node_modules'
            worktree = '/srv/example/.t3/worktrees/a/change'
            venv = '/srv/example/projects/a/.venv'
            entry.actions = [
                dict(tier='archive', action='would remove', path=scratch, bytes=20, reason='', category='scratch'),
                dict(tier='archive', action='would remove', path=modules, bytes=40, reason='', category='scratch'),
                dict(tier='worktree', action='would remove worktree', path=worktree, bytes=50, reason='', approval=True,
                     remote='https://github.com/example/a-source.git'),
                dict(tier='archive', action='would remove', path=venv, bytes=30, reason='', category='scratch'),
                dict(tier='archive', action='would remove', path=f'{worktree}/node_modules', bytes=10, reason='', category='scratch'),
                dict(tier='archive', action='skip', path=f'{scratch}/busy', bytes=100, reason='in use', category='scratch'),
            ]
            scanned = '2026-01-01T00:00:00+00:00'
            (reports / 'fleet').mkdir(parents=True)

            def snapshot():
                return {path.relative_to(root): (path.stat().st_mtime_ns, path.stat().st_ctime_ns,
                                                path.read_bytes() if path.is_file() else None)
                        for path in root.rglob('*')}

            def invoke(*args):
                return subprocess.run([sys.executable, '-B', '-m', 'coldcleaner', 'top', '--rules', str(config), '--json', *args],
                                      capture_output=True, text=True, timeout=3)

            def top():
                fleet.snapshot(reports, [entry], None, sha, {'example': scanned})
                before = snapshot()
                start = time.monotonic()
                result = invoke()
                elapsed = time.monotonic() - start
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(snapshot(), before)
                self.assertLess(elapsed, 3)
                return json.loads(result.stdout)

            worktree_item = dict(host='example', repo='a', tool='t3', category='worktree', path=worktree, bytes=50, approval=True)
            modules_item = dict(host='example', repo='b', tool='node', category='node_modules', path=modules, bytes=40, approval=False)
            venv_item = dict(host='example', repo='a', tool='python', category='venv', path=venv, bytes=30, approval=False)
            with self.subTest(mode='dry run'):
                self.assertEqual(top(), {
                    'schema_version': 1, 'status': 'ok', 'scanned': {'example': scanned}, 'missing_hosts': [],
                    'items': [worktree_item, modules_item, venv_item,
                              dict(host='example', repo='a', tool='unknown', category='scratch', path=scratch, bytes=20, approval=False)],
                    'totals': {'repo': {'a': 100, 'b': 40},
                               'tool': {'t3': 50, 'node': 40, 'python': 30, 'unknown': 20},
                               'category': {'worktree': 50, 'node_modules': 40, 'venv': 30, 'scratch': 20}},
                })

            entry.actions[0].update(action='archive and remove')
            entry.actions[1].update(action='skip', reason=reclaim.LIMIT_REACHED)
            entry.actions[2].update(action='skip', reason='IN USE: uncommitted work or stashes; ' + reclaim.APPROVAL_NEEDED)
            del entry.actions[2]['approval'], entry.actions[2]['remote']
            entry.actions[3].update(action='skip', reason=reclaim.APPROVAL_STALE)
            entry.actions[4].update(action='skip', reason=reclaim.LIMIT_REACHED)
            with self.subTest(mode='nightly apply'):
                self.assertEqual(top(), {
                    'schema_version': 1, 'status': 'ok', 'scanned': {'example': scanned}, 'missing_hosts': [],
                    'items': [worktree_item, modules_item, dict(venv_item, approval=True)],
                    'totals': {'repo': {'a': 80, 'b': 40}, 'tool': {'t3': 50, 'node': 40, 'python': 30},
                               'category': {'worktree': 50, 'node_modules': 40, 'venv': 30}},
                })

            with self.subTest(mode='invalid flag'):
                result = invoke('--apply')
                self.assertEqual(result.returncode, 1)
                self.assertEqual(json.loads(result.stdout), {
                    'schema_version': 1, 'status': 'refused', 'reason': 'invalid arguments; see stderr',
                })

            with self.subTest(mode='partial scan'):
                entry.notes.append('Unreadable, skipped: restricted folder')
                fleet.snapshot(reports, [entry], None, sha, {'example': scanned})
                before = snapshot()
                result = invoke()
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertTrue(result.stdout, result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    'schema_version': 1, 'status': 'incomplete', 'scanned': {}, 'missing_hosts': ['example'],
                    'items': [], 'totals': {'repo': {}, 'tool': {}, 'category': {}},
                })
                self.assertEqual(snapshot(), before)

            with self.subTest(mode='invalid snapshot'):
                (reports / 'fleet' / 'waiting.json').write_text('{')
                before = snapshot()
                result = invoke()
                self.assertEqual(result.returncode, 2)
                self.assertTrue(result.stdout, result.stderr)
                error = json.loads(result.stdout)
                self.assertEqual(error['schema_version'], 1)
                self.assertEqual(error['status'], 'incomplete')
                self.assertTrue(error['reason'])
                self.assertEqual(snapshot(), before)
