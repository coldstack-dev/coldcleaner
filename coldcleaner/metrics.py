import gzip
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import locking, report, store
from .report_files import is_apply, log_paths, timestamp, written

DAYS = 7
TIERS = ('worktree', 'clone', 'archive', 'rebuild')
USAGE = re.compile(r'(Before|After): ([\d.]+)% \([\d.]+ GiB \((\d+) bytes\) of [\d.]+ GiB \((\d+) bytes\)\)')
DRILL_RESULTS = ('pass', 'fail')
HUMAN_COMMANDS = ('approve', 'restore', 'find')


@dataclass
class HostMetrics:
    acted_bytes: int = 0
    acted: set = field(default_factory=set)
    held: set = field(default_factory=set)
    candidates: set = field(default_factory=set)
    recreated: set = field(default_factory=set)
    df_freed: int = 0
    used: list = field(default_factory=list)
    restored: int = 0
    human_actions: int = 0
    drill: tuple | None = None
    held_now: set | None = None
    held_starts: list = field(default_factory=list)

    @property
    def automation(self):
        waiting = len(self.held - self.acted)
        return len(self.acted) / (len(self.acted) + waiting) if self.acted or waiting else None


def actions(directory):
    lock = Path(directory) / 'reclaim-actions.lock'
    if not lock.exists():
        return read_actions(Path(directory))
    with lock.open() as stream:
        locking.lock(stream, shared=True)
        return read_actions(Path(directory))


def read_actions(directory):
    rows = []
    for path in log_paths(directory):
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rb') as stream:
            for number, line in enumerate(stream, 1):
                where = f'{path}:{number}'
                try:
                    row = json.loads(line.decode('utf-8'))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError(f'{where}: not UTF-8 JSON ({exc})') from None
                if not (isinstance(row, dict) and isinstance(row.get('host'), str) and isinstance(row.get('path'), str)
                        and isinstance(row.get('tier'), str) and isinstance(row.get('action'), str)
                        and isinstance(row.get('reason'), str) and type(row.get('bytes')) is int):
                    raise ValueError(f'{where}: missing host, path, tier, action, reason or bytes')
                row['at'] = timestamp(row.get('at'), where)
                rows.append(row)
    return sorted(rows, key=lambda row: row['at'])


def add_actions(found, rows, since):
    removed, held_since = {}, {}
    for row in rows:
        if row['tier'] not in TIERS:
            continue
        key = row['host'], row['path']
        entry = found.setdefault(row['host'], HostMetrics())
        recent = row['at'] >= since
        if recent and key in removed and row['at'] > removed[key]:
            entry.recreated.add(row['path'])
        if report.held(row):
            held_since.setdefault(key, row['at'])
        elif row['action'] != 'error':
            held_since.pop(key, None)
        if report.acted(row):
            removed[key] = row['at']
        if recent:
            entry.candidates.add(row['path'])
            if report.acted(row):
                entry.acted.add(row['path'])
                entry.acted_bytes += row['bytes']
            elif report.held(row):
                entry.held.add(row['path'])
    return held_since


def add_held(found, held_since, directory, current):
    state = Path(directory) / 'held.json'
    held = {name: paths for name, (_, paths) in report.held_state(state).items()} if state.exists() else {}
    for entry in current:
        now = {row['path'] for row in entry.actions if report.held(row)}
        held[entry.name] = now | held.get(entry.name, set()) if report.incomplete(entry) else now
    for name, paths in held.items():
        entry = found.setdefault(name, HostMetrics())
        entry.held_now = paths
        entry.held_starts = [held_since.get((name, path)) for path in paths]


def add_usage(found, host, before, after):
    entry = found.setdefault(host, HostMetrics())
    entry.df_freed += before[1] - after[1]
    entry.used.append(after[0])


def apply_usage(path):
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    if not is_apply(lines):
        return None
    found, host, usage = {}, None, {}
    for line in lines + ['## ']:
        if line.startswith('## '):
            if host and {'Before', 'After'} <= set(usage):
                found[host] = usage['Before'], usage['After']
            host, usage = line[3:], {}
        elif match := USAGE.fullmatch(line):
            usage[match.group(1)] = float(match.group(2)), int(match.group(3))
    return found


def add_disk(found, directory, since, current):
    for path in report.paths(directory):
        if written(path) < since:
            continue
        for host, (before, after) in (apply_usage(path) or {}).items():
            add_usage(found, host, before, after)
    for entry in current:
        if entry.before and entry.after:
            add_usage(found, entry.name, (entry.before.percent, entry.before.used), (entry.after.percent, entry.after.used))


def add_restores(found, nas_root):
    for record in store._read_index(Path(nas_root)):
        if record.status == 'restored':
            found.setdefault(record.host, HostMetrics()).restored += 1


def add_drills(found, directory):
    path = Path(directory) / 'restore-drill.jsonl'
    if not path.exists():
        return
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        where = f'{path}:{number}'
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f'{where}: not JSON ({exc})') from None
        if not (isinstance(row, dict) and isinstance(row.get('host'), str) and isinstance(row.get('id'), str)
                and row.get('result') in DRILL_RESULTS):
            raise ValueError(f'{where}: needs host, id and result pass or fail')
        at = timestamp(row.get('at'), where)
        entry = found.setdefault(row['host'], HostMetrics())
        if entry.drill is None or at >= entry.drill[0]:
            entry.drill = at, row['result'], row['id']


def add_human_actions(found, directory, since, now):
    path = Path(directory) / 'storage-time.jsonl'
    try:
        stream = path.open(encoding='utf-8')
    except FileNotFoundError:
        return
    with stream:
        locking.lock(stream, shared=True)
        for number, line in enumerate(stream, 1):
            where = f'{path}:{number}'
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f'{where}: not JSON ({exc})') from None
            if not isinstance(row, dict):
                raise ValueError(f'{where}: expected an object')
            if 'command' not in row:
                continue
            host, items = row.get('host'), row.get('items')
            if row['command'] not in HUMAN_COMMANDS or not isinstance(host, str) or not host or type(items) is not int or items < 0:
                raise ValueError(f'{where}: expected a host, human command and non-negative item count')
            if since <= timestamp(row.get('at'), where) <= now:
                found.setdefault(host, HostMetrics()).human_actions += 1


def compute(directory, nas_root, days=DAYS, now=None, current=()):
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    found = {}
    held_since = add_actions(found, actions(directory), since)
    add_held(found, held_since, directory, current)
    add_disk(found, directory, since, current)
    if nas_root is not None:
        add_restores(found, nas_root)
    add_drills(found, directory)
    add_human_actions(found, directory, since, now)
    return dict(sorted(found.items()))


def oldest(entry, now):
    if entry.held_now is None:
        return 'unknown (no held.json)'
    if not entry.held_now:
        return 'none'
    known = [start for start in entry.held_starts if start is not None]
    if not known:
        return 'unknown (not in the action log)'
    days = f'{(now - min(known)).total_seconds() / 86400:.1f} days'
    return days if len(known) == len(entry.held_starts) else 'at least ' + days


def gib(value):
    return f'{value / 1024**3:.2f}'


def render(found, days=DAYS, now=None):
    now = now or datetime.now(timezone.utc)
    lines = [f'Last {days} days, from the reclaim --apply action log, reports and storage-time.jsonl. '
             'Disk history uses retained reports. Restores count all INDEX rows with status restored.', '',
             '| Host | Reclaimed GiB (acted) | Disk freed GiB (df) | Candidates | Acted | Held for a person | Automation rate '
             f'| Recreated after removal | Restores | Human actions ({days}d) | Restore drill | Disk used | Oldest held |',
             '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |']
    for name, entry in found.items():
        rate = 'n/a' if entry.automation is None else f'{entry.automation:.0%}'
        drill = f'{entry.drill[1]} {entry.drill[0]:%Y-%m-%d} ({entry.drill[2]})' if entry.drill else 'none recorded'
        trend = f'{entry.used[0]:.2f}% -> {entry.used[-1]:.2f}%' if entry.used else 'n/a'
        values = (name, gib(entry.acted_bytes), gib(entry.df_freed), len(entry.candidates), len(entry.acted),
                  len(entry.held - entry.acted), rate, len(entry.recreated), entry.restored, entry.human_actions,
                  drill, trend, oldest(entry, now))
        lines.append('| ' + ' | '.join(map(report.cell, values)) + ' |')
    if not found:
        lines.append('| (no data) | | | | | | | | | | | | |')
    return lines
