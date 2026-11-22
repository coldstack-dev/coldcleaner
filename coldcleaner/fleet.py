import os
import json
import re
import shlex
from html import escape
import socket
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import collect, locking, metrics, reclaim, report, report_files, rules

RUNS = 30
REPORT_RETENTION = 30
TOP = 5
NAME = Path('fleet', 'summary.md')
SNAPSHOT = NAME.with_name('waiting.json')
BARS = '▁▂▃▄▅▆▇█'
MANAGED_SAMPLE = re.compile(re.escape(report.MANAGED) + r'[0-9]+\.[0-9]{2} GiB \(([0-9]+) bytes\); coverage (complete|partial)')


def recent_runs(directory, collected=()):
    reports = [(path, None) for path in report.paths(directory)]
    reports.extend((path, host) for host, paths in collected for path in paths)
    runs = []
    for path, host in sorted(reports, key=lambda item: item[0].stem, reverse=True):
        usage = metrics.apply_usage(path)
        if usage is None or (host is not None and host not in usage):
            continue
        runs.append((metrics.written(path), usage if host is None else {host: usage[host]}))
        if len(runs) > RUNS:
            break
    runs.reverse()
    return (runs[0][0], runs[1:]) if len(runs) > RUNS else (None, runs)


def held_now(rows, directory, collected):
    latest = {}
    for row in rows:
        if row['tier'] in metrics.TIERS and row['action'] != 'error':
            latest[row['host'], row['path']] = row
    state = report.held_state(Path(directory) / 'held.json')
    found = defaultdict(list)
    for (host, path), row in latest.items():
        if report.held(row) and (host in collected or host not in state or path in state[host][1]):
            found[host].append(row)
    return found


def reclaimed(rows, since, runs):
    found = defaultdict(int)
    until = runs[-1][0] if runs else None
    for row in rows:
        if (until and row['tier'] in metrics.TIERS and report.acted(row)
                and (since is None or row['at'] > since) and row['at'] <= until):
            found[row['host']] += row['bytes']
    return found


def sparkline(values):
    low, high = min(values), max(values)
    return ''.join(BARS[round((value - low) / (high - low) * (len(BARS) - 1)) if high > low else 3] for value in values)


def disk_cells(values):
    if not values:
        return ['no apply runs', 'n/a', 'n/a', 'n/a']
    return [f'{sparkline(values)} ({len(values)} runs)', *(f'{value:.2f}%' for value in (values[-1], min(values), max(values)))]


def managed_history(directory, collected, names, now):
    window = timedelta(days=30)
    samples = defaultdict(list)
    latest_complete = {}
    baselines = {}
    pending = set()
    reports = [(path, None) for path in report.paths(directory)]
    reports.extend((path, host) for host, paths in collected.items() for path in paths)
    for path, collected_host in sorted(reports, key=lambda item: item[0].stem, reverse=True):
        at = metrics.written(path)
        if at > now:
            continue
        older = at < now - window
        if older and not pending:
            break
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
        if not report_files.is_apply(lines):
            continue
        policy = next((match[1] for line in lines if
                       (match := re.fullmatch(r'Rules: sha256 ([0-9a-f]{64})', line))), None)
        host = None
        for line in lines:
            if line.startswith('## '):
                name = line[3:]
                host = name if name in names and collected_host in (None, name) else None
                if host and not older:
                    samples[host].append((at, None, 'unavailable', policy))
            elif host and (match := MANAGED_SAMPLE.fullmatch(line)):
                value = (at, int(match[1]), match[2], policy)
                if not older:
                    samples[host][-1] = value
                    if match[2] == 'complete':
                        if host not in latest_complete and policy:
                            pending.add(host)
                        latest = latest_complete.setdefault(host, value)
                        if policy == latest[3] and latest[0] - at >= window:
                            pending.discard(host)
                elif (host in pending and match[2] == 'complete'
                      and policy == latest_complete[host][3] and latest_complete[host][0] - at >= window):
                    baselines[host] = value
                    pending.remove(host)
                host = None
    return samples, baselines


def managed_target(target, rows):
    if target is None:
        return 'no target'
    if not rows or rows[0][2] != 'complete':
        return f'{target} bytes (latest observation incomplete)'
    difference = rows[0][1] - target
    status = 'at target' if difference == 0 else f"{abs(difference)} bytes {'over' if difference > 0 else 'under'}"
    return f'{target} bytes ({status})'


def managed_trend(rows, baseline):
    complete = [value for value in rows if value[2] == 'complete']
    if not complete:
        return '0 days covered'
    end, last, _, policy = complete[0]
    start, first, _, _ = baseline or next(
        (value for value in reversed(complete) if policy and value[3] == policy), complete[0])
    days = (end - start).days
    span = f'{days} {"day" if days == 1 else "days"} covered'
    change = f'30-day trend: {last - first:+d} bytes' if days >= 30 else 'insufficient coverage for trend'
    return f'{start:%Y-%m-%d} → {end:%Y-%m-%d}: {span}, {change}'


def managed_section(directory, collected, names, now, host_rules):
    samples, baselines = managed_history(directory, collected, set(names), now)
    lines = ['', '## Managed agent-artifact bytes (30 days)', '',
             'Bytes estimated from measured file allocation in listed archive paths, worktrees and clones at the end of apply scans.',
             'Trends compare complete observations with matching rules hashes. Counts cover the last 30 days.', '',
             '| Host | Latest apply observation | Complete observations | Coverage (complete / partial / unavailable) | Target |',
             '| --- | --- | --- | --- | --- |']
    for name in names:
        rows = samples[name]
        latest = 'no apply reports'
        if rows:
            at, size, coverage, _ = rows[0]
            amount = coverage if size is None else f'{report.size(size)}, {coverage}'
            latest = f'{at:%Y-%m-%d}: {amount}'
        counts = [sum(row[2] == state for row in rows) for state in ('complete', 'partial', 'unavailable')]
        target = host_rules.get(name, {}).get('managed_bytes_target')
        cells = (name, latest, managed_trend(rows, baselines.get(name)), ' / '.join(map(str, counts)),
                 managed_target(target, rows))
        lines.append('| ' + ' | '.join(map(report.cell, cells)) + ' |')
    return lines


def policy_cells(host_rules):
    if host_rules is None:
        return ['not configured', '', '']
    overrides = [f'{pattern} {days} days' for pattern in rules.archive_patterns(host_rules)
                 if (days := rules.archive_entry(host_rules, pattern)['days']) is not None]
    return [len(host_rules.get('roots', [])), len(rules.archive_patterns(host_rules)), ', '.join(overrides) or 'none']


def policy(config):
    merged = min(config['worktree_idle_days'], reclaim.WORKTREE_MERGED_DAYS)
    return (f"Policy: live = {', '.join(config['live']) or 'none'}; worktree idle {config['worktree_idle_days']} days "
            f"({merged} once merged); archive idle {config['archive_idle_days']} days (at least 7 for system temp folders).")


def held_section(name, rows):
    lines = [f'### {name}', '', '| Held because | Worktrees | GiB | To release |', '| --- | ---: | ---: | --- |']
    for reason, todo in report.HELD.items():
        matched = [row for row in rows if report.held(row) == reason]
        if matched:
            lines.append(f"| {reason} | {len(matched)} | {metrics.gib(sum(row['bytes'] for row in matched))} | {todo} |")
    lines.extend(['', f'Top {TOP} held directories:', '', '| Path | GiB | Reason |', '| --- | ---: | --- |'])
    for row in sorted(rows, key=lambda row: (-row['bytes'], row['path']))[:TOP]:
        lines.append('| ' + ' | '.join(map(report.cell, (row['path'], metrics.gib(row['bytes']), row['reason']))) + ' |')
    return lines + ['']


def event(directory, **values):
    path = Path(directory) / 'storage-time.jsonl'
    with path.open('a') as stream:
        locking.lock(stream)
        stream.write(json.dumps(dict(at=datetime.now(timezone.utc).isoformat(), **values)) + '\n')


def weekly(directory, now):
    path = Path(directory) / 'storage-time.jsonl'
    recent, invalid = [], 0
    if path.exists():
        with path.open() as stream:
            locking.lock(stream, shared=True)
            for line in stream:
                try:
                    row = json.loads(line)
                    at = metrics.timestamp(row['at'], path)
                    if now - timedelta(days=7) <= at <= now:
                        if any(type(row.get(key, 0)) not in (int, float) for key in ('seconds', 'approvals')):
                            raise ValueError('invalid count')
                        recent.append(row)
                except (ValueError, KeyError, TypeError):
                    invalid += 1
    return (f"Last 7 days: {sum(row.get('seconds', 0) for row in recent) / 60:.1f} minutes of reclaim run time; "
            f"{sum(row.get('approvals', 0) for row in recent)} item approvals. "
            "Includes manual runs and dry runs. Recorded since installation; human time is not measured. "
            + (f'{invalid} unreadable telemetry lines omitted.' if invalid else ''))


def read_snapshot(directory):
    try:
        return json.loads((Path(directory) / SNAPSHOT).read_text())
    except FileNotFoundError:
        return {}


def snapshot(directory, reports, plan, policy, scanned):
    path = Path(directory) / SNAPSHOT
    state = read_snapshot(directory)
    for entry in reports:
        at = scanned.get(entry.name, datetime.now(timezone.utc).isoformat())
        previous = state.get(entry.name, {}).get('scanned')
        if previous and metrics.timestamp(at, path) < metrics.timestamp(previous, path):
            continue
        state[entry.name] = dict(rows=entry.actions, plan=str(plan.resolve()) if plan else None,
                                 rules_sha256=policy, errors=entry.errors, scanned=at,
                                 managed_complete=not report.managed_partial(entry))
    temporary = path.with_suffix('.tmp')
    try:
        temporary.write_text(json.dumps(state))
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def waiting(directory, config, rows, held, collected):
    latest = {}
    for row in rows:
        if row['tier'] in metrics.TIERS and row['action'] != 'error':
            latest[row['host'], row['tier'], row['path']] = row
    state = read_snapshot(directory)
    lines = ['## Waiting list', '', 'Owner is not recorded by cleanup; confirm the owner before acting.', '',
             'Latest host report actions, including unsized safety holds. Hosts without a snapshot use the action log.', '',
             '| Host | Path | Reason | Owner | Approve command or next action |', '| --- | --- | --- | --- | --- |']
    for host, entry in state.items():
        if host in collected:
            continue
        latest = {key: row for key, row in latest.items() if key[0] != host}
        if entry['errors']:
            lines.append('| ' + report.cell(host) + ' | Scan incomplete | See run report | Unassigned | Rerun reclaim |')
        for row in entry['rows']:
            latest[host, row['tier'], row['path']] = dict(row, host=host)
    for key, row in sorted(latest.items()):
        if (row['host'] not in state or row['host'] in collected) and report.held(row) and row not in held[row['host']]:
            continue
        if row['tier'] not in metrics.TIERS:
            continue
        gated = row.get('approval', False) and row['action'].startswith('would ')
        if row['action'] != 'skip' and not gated:
            continue
        reason = report.held(row)
        command = report.HELD.get(reason, 'Resolve the reported hold; approval cannot override safety checks')
        if gated:
            entry = state.get(row['host'], {})
            if (entry.get('plan') and entry.get('rules_sha256') == config.get('rules_sha256')
                    and reclaim.ITEM_ID.fullmatch(row.get('id', ''))):
                command = shlex.join(['python3', '-m', 'coldcleaner', 'approve', '--report-dir',
                                      str(Path(directory).resolve()), entry['plan'], row['id']])
            else:
                command = 'Run a fresh reclaim dry run to obtain a current approval ID'
        elif 'approval' in row['reason'].lower():
            command = 'Run a fresh reclaim dry run to obtain a current approval ID'
        elif reason:
            command += '; approval cannot override this hold'
        lines.append('| ' + ' | '.join(map(report.cell, (row['host'], row['path'], row['reason'],
                                                        'Unassigned', command))) + ' |')
    return lines + ['']


def collected_reports(config):
    collected, invalid = {}, []
    for name, directory in collect.directories(config).items():
        collected[name] = []
        for path in report.paths(directory):
            try:
                if path.is_symlink() or not path.is_file():
                    raise ValueError('not a regular report')
                metrics.written(path)
                text = path.read_text(encoding='utf-8')
                if not report_files.reclaim_mode(text.splitlines()) or not report_files.host_lines(text, name):
                    raise ValueError('invalid reclaim report')
            except (OSError, ValueError):
                invalid.append(f'- {name}: ignored invalid collected report {path.name}')
            else:
                collected[name].append(path)
    return collected, invalid


def current_collected(collected):
    current = {}
    for name, paths in collected.items():
        for path in reversed(paths):
            text = path.read_text(encoding='utf-8')
            if report_files.is_apply(text.splitlines()):
                current[name] = metrics.written(path), set(report_files.host_lines(text, name))
                break
    return current


def html(lines):
    body, table = [], False
    for line in lines:
        if line.startswith('|'):
            cells = line.strip('|').split(' | ')
            if all(set(cell.strip()) <= set('-: ') for cell in cells):
                continue
            tag = 'td' if table else 'th'
            if not table:
                body.append('<table>')
                table = True
            body.append('<tr>' + ''.join(f'<{tag}>' + escape(cell.strip()) + f'</{tag}>' for cell in cells) + '</tr>')
            continue
        if table:
            body.append('</table>')
            table = False
        if line.startswith('#'):
            title = line.split(' ', 1)
            level = len(title[0])
            body.append(f'<h{level}>' + escape(title[1]) + f'</h{level}>')
        elif line:
            body.append('<p>' + escape(line) + '</p>')
    if table:
        body.append('</table>')
    return ('<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src &apos;none&apos;; style-src &apos;unsafe-inline&apos;">'
            '<title>Coldcleaner fleet</title><style>body{font:16px system-ui;margin:2rem;color:#17212b;background:#fff}'
            'table{border-collapse:collapse;display:block;overflow:auto}th,td{padding:.6rem;border:1px solid #aaa;'
            'text-align:left}th{background:#edf2f7}td:last-child{overflow-wrap:anywhere}h1,h2{color:#163e66}'
            '</style><main>' + ''.join(body) + '</main></html>')


def render(config, now=None, *, retained_since=None):
    now = now or datetime.now(timezone.utc)
    directory = config['report_dir']
    collected, invalid = collected_reports(config)
    since, runs = recent_runs(directory, collected.items())
    if since is None and runs and retained_since is not None:
        since = min(retained_since, runs[0][0])
    rows = metrics.actions(directory)
    current = current_collected(collected)
    current_rows = []
    for row in rows:
        marker = current.get(row['host'])
        if marker is None or (row['at'] <= marker[0] and report.action_line(row) in marker[1]):
            current_rows.append(row)
    held, acted = held_now(current_rows, directory, current), reclaimed(rows, since, runs)
    names = [name for name, table in config['hosts'].items() if table['kind'] != 'wsl']
    names += sorted(({name for _, usage in runs for name in usage} | set(held) | set(acted)) - set(names))
    window = f'the last {len(runs)} reclaim --apply runs (from {runs[0][0]:%Y-%m-%d})' if runs else 'no reclaim --apply runs yet'
    start = ''
    if since:
        start = f' Reclaimed counts actions after {since:%Y-%m-%d %H:%M:%S} UTC.'
    elif runs:
        start = (' With 30 or fewer apply reports there is no earlier report to start from, '
                 'so reclaimed counts every logged action up to the newest one.')
    lines = ['# coldcleaner fleet', '', f'Updated {now:%Y-%m-%d %H:%M} UTC. Disk used (after each run) and reclaimed cover {window}.{start} '
             'Held is the current state from the action log and held.json.', '', policy(config), '',
             '| Host | Disk used | Latest | Min | Max | Reclaimed GiB | Held | Held GiB | Roots | Archive patterns | Archive days overrides |',
             '| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |']
    for name in names:
        values = [usage[name][1][0] for _, usage in runs if name in usage]
        cells = [name, *disk_cells(values), metrics.gib(acted[name]), len(held[name]),
                 metrics.gib(sum(row['bytes'] for row in held[name])), *policy_cells(config['hosts'].get(name))]
        lines.append('| ' + ' | '.join(map(report.cell, cells)) + ' |')
    lines.extend(managed_section(directory, collected, names, now, config['hosts']))
    if collected:
        lines.extend(['', '## Collected local reports', ''])
        for name, paths in collected.items():
            latest = paths[-1].name if paths else 'none yet'
            lines.append(f'- {name}: {latest}')
        lines.extend(invalid)
        lines.extend(['', 'Collected action and hold rows are limited to the rows printed in each local report.'])
    lines.extend(['', '## Held for a person', ''])
    for name in names:
        if held[name]:
            lines.extend(held_section(name, held[name]))
    if not any(held.values()):
        lines.extend(['None.', ''])
    lines.extend(waiting(directory, config, current_rows, held, current))
    lines.extend(['## Time spent on storage', '', weekly(directory, now), ''])
    return lines


def write(config, now=None, *, seconds=None, reports=None, plan=None, scanned=None, run_report=None):
    path = Path(config['report_dir']) / NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    with (Path(config['report_dir']) / 'fleet.lock').open('a') as lock:
        locking.lock(lock)
        if reports is not None:
            snapshot(config['report_dir'], reports, plan, config.get('rules_sha256'), scanned or {})
        if seconds is not None:
            event(config['report_dir'], seconds=seconds)
        retained_since = None
        if run_report is not None:
            try:
                retained_since = prune(config, run_report, plan)
            except (OSError, ValueError, EOFError) as exc:
                print(f'coldcleaner: report retention incomplete: {exc}', file=sys.stderr, flush=True)
        try:
            lines = render(config, now, retained_since=retained_since)
        except Exception as exc:
            lines = ['# coldcleaner fleet', '', 'Fleet summary unavailable: ' + report.cell(exc), '']
        for target, content in [(path, '\n'.join(lines) + '\n'), (path.with_suffix('.html'), html(lines))]:
            temporary = target.with_suffix(f'.{socket.gethostname()}.{os.getpid()}.tmp')
            try:
                temporary.write_text(content, encoding='utf-8', errors='backslashreplace')
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
    return path


def prune(config, current_report, current_plan):
    directory = Path(config['report_dir'])
    policy = config.get('rules_sha256')
    reports = [path for path in reversed(report.paths(directory)) if not path.is_symlink() and path.is_file()]
    plans = sorted((path for path in directory.glob('*.plan.json')
                    if re.fullmatch(report_files.PLAN_FILENAME, path.name)
                    and not path.is_symlink() and path.is_file()), reverse=True)
    if max(len(reports), len(plans)) <= REPORT_RETENTION:
        return

    kept_reports = {current_report}
    kept_plans = {current_plan}
    covered = set()
    owned_reports = []
    for path in reports:
        with path.open(encoding='utf-8', errors='replace') as stream:
            if not re.fullmatch(r'# coldcleaner [0-9-]+ [0-9:]+ UTC', stream.readline().rstrip()):
                continue
        owned_reports.append(path)
        if policy:
            hosts = report.dry_run_hosts(path, policy)
            if hosts - covered:
                kept_reports.add(path)
                kept_plans.add(path.with_suffix('.plan.json'))
                covered.update(hosts)

    expired_plans = plans[REPORT_RETENTION:]
    if expired_plans:
        if policy:
            for path in plans:
                payload = json.loads(path.read_text(encoding='utf-8'))
                if not isinstance(payload, dict):
                    raise ValueError(f'{path} is not a reclaim dry-run plan')
                if payload.get('rules_sha256') == policy:
                    kept_plans.add(path)
                    break

        with reclaim.approvals(directory) as approvals, (directory / 'reclaim-actions.lock').open('a') as log_lock:
            locking.lock(log_lock, shared=True)
            state = read_snapshot(directory)
            if not isinstance(state, dict) or not all(isinstance(row, dict) for row in state.values()):
                raise ValueError('invalid fleet snapshot')
            rows = (*approvals.values(), *state.values(), *metrics.read_actions(directory))
            referenced_plans = set()
            for row in rows:
                reference = row.get('plan')
                if reference is not None:
                    if not isinstance(reference, str) or not reference:
                        raise ValueError('invalid plan reference')
                    referenced_plans.add(Path(reference).name)
            for path in expired_plans:
                if path not in kept_plans and path.name not in referenced_plans:
                    path.unlink(missing_ok=True)

    for path in owned_reports[REPORT_RETENTION:]:
        if path not in kept_reports:
            path.unlink(missing_ok=True)
    if len(owned_reports) > REPORT_RETENTION:
        return report_files.written(owned_reports[REPORT_RETENTION - 1])
