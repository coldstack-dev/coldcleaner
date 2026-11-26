import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from coldcleaner import fleet, reclaim, report, rules

GIB = 1024**3
STALE = 'IN USE: work is neither merged nor closed at this head'
DIRTY = 'IN USE: uncommitted work or stashes'
ABANDONED = f'ABANDONED: {DIRTY}; idle 30 days; approval required; whole tree and Git history go to a verified NAS copy'


class TriageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.reports = self.root / 'reports'
        (self.reports / 'fleet').mkdir(parents=True)
        self.config = self.root / 'rules.toml'
        self.config.write_text(
            f'alert_pct = 80\nworktree_idle_days = 7\narchive_idle_days = 4\n'
            f'nas_root = {json.dumps(str(self.root / "nas"))}\nreport_dir = {json.dumps(str(self.reports))}\n'
            'live = ["worktree", "archive"]\nalready_compressed_extensions = []\n[hosts.example]\nkind = "posix"\n'
        )
        self.sha = rules.load(self.config)['rules_sha256']
        self.stale = '/srv/example/projects/alpha/.worktrees/stale'
        self.old = '/srv/example/.t3/worktrees/beta/old'
        self.young = '/srv/example/.t3/worktrees/beta/young'
        entry = report.HostReport('example')
        entry.actions = [
            dict(tier='worktree', action='skip', path=self.stale, bytes=3 * GIB, reason=STALE, rule='r', idle_days=7),
            dict(tier='worktree', action='would archive abandoned worktree', path=self.old, bytes=GIB, reason=ABANDONED,
                 rule='r', idle_days=30, id='a' * 16, approval=True),
            dict(tier='worktree', action='would archive abandoned worktree', path=self.young, bytes=GIB, reason=ABANDONED,
                 rule='r', idle_days=30, id='b' * 16, approval=True),
            dict(tier='archive', action='would archive and remove', path='/srv/example/scratch', bytes=GIB, reason='',
                 rule='r', idle_days=4),
        ]
        now = datetime.now(timezone.utc)
        fleet.snapshot(self.reports, [entry], None, self.sha, {'example': now.isoformat()})
        stem = self.reports / f'{now:%Y-%m-%d-%H%M%S}-000000-{"0" * 32}'
        stem.with_suffix('.md').write_text(report.render([entry], rules_sha256=self.sha, reclaim=True))
        self.plan = reclaim.write_plan(stem.with_suffix('.plan.json'), [entry], self.sha)
        seen = dict(((self.stale, 100), (self.old, 60), (self.young, 5)))
        (self.reports / 'reclaim-actions.jsonl').write_text(''.join(
            json.dumps(dict(host='example', at=(now - timedelta(days=days)).isoformat(), tier='worktree', action='skip',
                            path=path, bytes=GIB, reason=STALE)) + '\n' for path, days in seen.items()))

    def triage(self, *args):
        result = subprocess.run([sys.executable, '-B', '-m', 'coldcleaner', 'triage', '--rules', str(self.config), *args],
                                capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout + result.stderr

    def approvals(self):
        path = self.reports / reclaim.APPROVALS
        return json.loads(path.read_text()) if path.exists() else {}

    def test_summary_groups_held_worktrees_by_reason_repo_and_age(self):
        code, output = self.triage()
        self.assertEqual(code, 0, output)
        self.assertIn('Held worktrees: 3 (5.00 GiB)', output)
        self.assertIn(f'      1     3.00 GiB  {STALE} (to release: {report.HELD[STALE]})', output)
        self.assertIn(f'      2     2.00 GiB  {DIRTY}', output)
        self.assertIn('      2     2.00 GiB  beta', output)
        self.assertIn('      1     3.00 GiB  alpha', output)
        self.assertIn('      1     1.00 GiB  under 7 days', output)
        self.assertIn('      1     3.00 GiB  90 days or more', output)
        oldest = output.split('Oldest 10:\n')[1].splitlines()
        self.assertEqual([line.split()[0] for line in oldest], ['100d', '60d', '5d'])
        self.assertNotIn('/srv/example/scratch', output)
        self.assertEqual(self.approvals(), {})

    def test_archive_older_than_lists_then_approves_only_old_abandoned_worktrees(self):
        code, output = self.triage('--archive-older-than', '30', '--dry-run')
        self.assertEqual(code, 0, output)
        self.assertIn('Would approve 1 abandoned worktrees', output)
        self.assertIn(self.old, output)
        self.assertNotIn(self.young, output.split('Would approve')[1])
        self.assertEqual(self.approvals(), {})
        code, output = self.triage('--archive-older-than', '30', '--apply')
        self.assertEqual(code, 0, output)
        self.assertIn('Approved 1 abandoned worktrees', output)
        approved = self.approvals()
        self.assertEqual(list(approved), ['a' * 16])
        self.assertEqual(approved['a' * 16]['path'], self.old)
        self.assertEqual(approved['a' * 16]['plan'], str(Path(self.plan).resolve()))

    def test_plans_under_other_rules_are_ignored_and_apply_needs_a_threshold(self):
        self.config.write_text(self.config.read_text().replace('alert_pct = 80', 'alert_pct = 81'))
        code, output = self.triage('--archive-older-than', '1')
        self.assertEqual(code, 0, output)
        self.assertIn('No abandoned worktrees in the current-rules plans match.', output)
        code, output = self.triage('--apply')
        self.assertNotEqual(code, 0)
        self.assertIn('--archive-older-than', output)
        self.assertEqual(self.approvals(), {})


if __name__ == '__main__':
    unittest.main()
