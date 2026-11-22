import re
from collections import Counter

from . import fleet, reclaim, report

DEPENDENCIES = {'.venv': ('venv', 'python'), 'venv': ('venv', 'python'), 'node_modules': ('node_modules', 'node')}
TOOLS = {'.t3': 't3', '.codex': 'codex', '.claude': 'claude'}
APPROVAL_SUFFIXES = tuple('; ' + reason for reason in (reclaim.APPROVAL_NEEDED, reclaim.APPROVAL_STALE))


def attribution(row):
    parts = re.split(r'[/\\]+', row['path'].rstrip('/\\'))
    names = [part.casefold() for part in parts]
    dependency = DEPENDENCIES.get(names[-1]) if row['tier'] == 'archive' else None
    category = dependency[0] if dependency else report.category(row) or 'scratch'
    tool = next((TOOLS[name] for name in names if name in TOOLS), dependency[1] if dependency else 'unknown')
    repo = next((parts[index + 1] for index, name in enumerate(names[:-1]) if name in ('projects', 'repos')), 'unknown')
    if repo == 'unknown':
        for index in range(len(parts) - 1):
            if names[index] == 'worktrees':
                offset = 2 if index and names[index - 1] == '.codex' else 1
                if index + offset < len(parts):
                    repo = parts[index + offset]
                break
    if repo == 'unknown' and row.get('remote'):
        try:
            repo = reclaim.repository(row['remote'])
        except ValueError:
            pass
    return repo, tool, category


def candidates(rows):
    pending, removed = [], []
    for index, row in enumerate(rows):
        if row['tier'] not in ('worktree', 'archive', 'clone'):
            continue
        if report.acted(row):
            removed.append((index, row))
            continue
        if row['tier'] == 'clone' or row['bytes'] <= 0:
            continue
        reason = row['reason']
        needs_approval = row['action'] == 'skip' and ('; ' + reason).endswith(APPROVAL_SUFFIXES)
        if row['action'].startswith('would ') or needs_approval or (row['action'] == 'skip' and reason == reclaim.LIMIT_REACHED):
            pending.append((index, dict(row, approval=needs_approval or row.get('approval', False))))
    return report.remaining(pending, removed)


def breakdown(config, hosts):
    state = fleet.read_snapshot(config['report_dir'])
    scanned, missing, items = {}, [], []
    for host in hosts:
        entry = state.get(host.name)
        if not entry or entry['rules_sha256'] != config['rules_sha256'] or entry.get('managed_complete') is not True:
            missing.append(host.name)
            continue
        scanned[host.name] = entry['scanned']
        for row, size in candidates(entry['rows']):
            if not size:
                continue
            repo, tool, category = attribution(row)
            items.append(dict(host=host.name, repo=repo, tool=tool, category=category, path=row['path'],
                              bytes=size, approval=row['approval']))
    items.sort(key=lambda item: (-item['bytes'], item['host'], item['path']))
    totals = {}
    for field in ('repo', 'tool', 'category'):
        counts = Counter()
        for item in items:
            counts[item[field]] += item['bytes']
        totals[field] = dict(counts.most_common())
    return dict(status='incomplete' if missing else 'ok', scanned=scanned, missing_hosts=missing, items=items, totals=totals)


def print_breakdown(result):
    for host, scanned in result['scanned'].items():
        print(f'{host} scanned {scanned}')
    for host in result['missing_hosts']:
        print(f'{host} has no complete scan under the current rules')
    if result['items']:
        print('Bytes\tHost\tRepo\tTool\tCategory\tApproval\tPath')
        for row in result['items']:
            print('\t'.join(report.cell(row[key]) for key in ('bytes', 'host', 'repo', 'tool', 'category', 'approval', 'path')))
    elif result['scanned']:
        print('No reclaimable clutter in the available scans.')
