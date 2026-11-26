import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from . import fleet, metrics, reclaim, report, report_files, top

AGES = ((7, 'under 7 days'), (30, '7 to 29 days'), (90, '30 to 89 days'), (None, '90 days or more'))
SHOWN = 10


def hold(row):
    if row['tier'] != 'worktree' or row['action'] not in ('skip', 'would archive abandoned worktree'):
        return None
    text = row['reason'].removeprefix('ABANDONED: ')
    return next((reason for reason in report.HELD if text.startswith(reason)), None)


def held(config, hosts, now=None):
    now = now or datetime.now(timezone.utc)
    first = {}
    for row in metrics.actions(config['report_dir']):
        first.setdefault((row['host'], row['path']), row['at'])
    items = []
    for host, entry in fleet.read_snapshot(config['report_dir']).items():
        if host not in hosts:
            continue
        scanned = metrics.timestamp(entry['scanned'], fleet.SNAPSHOT)
        for row in entry['rows']:
            if reason := hold(row):
                since = min(first.get((host, row['path']), scanned), scanned)
                items.append(dict(host=host, path=row['path'], bytes=row['bytes'], reason=reason,
                                  repo=top.attribution(row)[0], age=(now - since).days))
    return sorted(items, key=lambda item: (-item['age'], -item['bytes'], item['host'], item['path']))


def bucket(age):
    return next(label for limit, label in AGES if limit is None or age < limit)


def group(items, key):
    found = defaultdict(lambda: [0, 0])
    for item in items:
        found[key(item)][0] += 1
        found[key(item)][1] += item['bytes']
    return found


def summary(items):
    if not items:
        return ['No held worktrees in the latest scans.']
    gib = lambda value: f'{value / 1024**3:.2f} GiB'
    lines = [f"Held worktrees: {len(items)} ({gib(sum(item['bytes'] for item in items))}); "
             'age is days since coldcleaner first logged the path', '', 'By reason:']
    reasons = group(items, lambda item: item['reason'])
    lines += [f'  {count:>5}  {gib(size):>11}  {reason} (to release: {report.HELD[reason]})'
              for reason, (count, size) in sorted(reasons.items(), key=lambda pair: -pair[1][1])]
    lines += ['', f'By repo (largest {SHOWN}):']
    repos = sorted(group(items, lambda item: item['repo']).items(), key=lambda pair: -pair[1][1])
    lines += [f'  {count:>5}  {gib(size):>11}  {repo}' for repo, (count, size) in repos[:SHOWN]]
    lines += ['', 'By age:']
    ages = group(items, lambda item: bucket(item['age']))
    lines += [f'  {ages[label][0]:>5}  {gib(ages[label][1]):>11}  {label}' for _, label in AGES if label in ages]
    lines += ['', f'Oldest {SHOWN}:']
    lines += [f"  {item['age']:>4}d  {gib(item['bytes']):>11}  {item['host']}  {report.cell(item['path'])}  {item['reason']}"
              for item in items[:SHOWN]]
    return lines


def plan_items(config, hosts=None):
    directory = Path(config['report_dir'])
    plans = sorted((path for path in directory.glob('*.plan.json') if re.fullmatch(report_files.PLAN_FILENAME, path.name)),
                   reverse=True)
    covered = set()
    for plan in plans:
        found = report.dry_run_hosts(Path(str(plan).removesuffix('.plan.json') + '.md'), config['rules_sha256']) - covered
        if not found:
            continue
        covered |= found
        for item in json.loads(plan.read_text()).get('items', []):
            if item['host'] in found and (hosts is None or item['host'] in hosts):
                yield dict(item, plan=plan)


def abandoned(config, items, days):
    ages = {(item['host'], item['path']): item['age'] for item in items}
    return [dict(item, age=ages[item['host'], item['path']]) for item in plan_items(config)
            if item['tier'] == 'worktree' and item['approval'] and item['reason'].startswith('ABANDONED: ')
            and ages.get((item['host'], item['path']), -1) >= days]


def rebuildable(config, hosts):
    items = sorted((item for item in plan_items(config, hosts) if item['tier'] == 'rebuild'), key=lambda item: -item['bytes'])
    if not items:
        return []
    lines = [f"Rebuildable caches awaiting approval: {len(items)} ({sum(item['bytes'] for item in items) / 1024**3:.2f} GiB), "
             f'deleted without a NAS copy once approved; largest {SHOWN}:']
    lines += [f"  {item['id']}  {item['bytes'] / 1024**3:>8.2f} GiB  {item['host']}  {report.cell(item['path'])}"
              for item in items[:SHOWN]]
    return [*lines, 'Approve with: coldcleaner approve PLAN <ids>; the next reclaim --apply rechecks and deletes each one.']


def archive(config, chosen, apply):
    lines = [f"  {item['id']}  {item['age']:>4}d  {item['bytes'] / 1024**3:.2f} GiB  {item['host']}  {report.cell(item['path'])}"
             for item in chosen]
    if not chosen:
        return ['No abandoned worktrees in the current-rules plans match.'], 0
    if not apply:
        return [f'Would approve {len(chosen)} abandoned worktrees for a verified NAS bundle:', *lines,
                'Dry run. Rerun with --apply to approve them.'], 0
    plans = defaultdict(list)
    for item in chosen:
        plans[item['plan']].append(item['id'])
    approved = [ident for plan, ids in plans.items() for ident in reclaim.approve(config['report_dir'], plan, ids)]
    return [f'Approved {len(approved)} abandoned worktrees:', *lines,
            'The next reclaim --apply rechecks each one, copies its whole tree and head.bundle to the NAS, '
            'verifies the copy, then removes it.'], len(approved)
