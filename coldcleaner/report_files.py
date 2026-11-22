import contextlib
import gzip
import itertools
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

RECLAIM = 'Command: reclaim'
REPORT_DATE = r'\d{4}-\d{2}-\d{2}'
RUN_SUFFIX = r'-\d{6}-\d{6}-[0-9a-f]{32}'
FILENAME = rf'{REPORT_DATE}(?:{RUN_SUFFIX})?\.md'
PLAN_FILENAME = rf'{REPORT_DATE}{RUN_SUFFIX}\.plan\.json'
ACTION_KEYS = ('at', 'host', 'tier', 'action', 'path', 'bytes', 'reason')


def cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')


def reported_action(row):
    if row.get('quarantine_path'):
        return 'quarantine'
    if row.get('quarantine_days') and row['action'] == 'would remove':
        return 'would quarantine'
    return row['action']


def action_line(row):
    values = [row['tier'], reported_action(row), row['path'], row['bytes'], row['reason']]
    return '| ' + ' | '.join(map(cell, values)) + ' |'


def host_lines(text, name):
    lines = iter(text.splitlines())
    for line in lines:
        if line == f'## {name}':
            return list(itertools.takewhile(lambda line: not line.startswith('## '), lines))
    return []


def reclaim_mode(lines):
    header = list(itertools.takewhile(lambda line: not line.startswith('## '), lines))
    if RECLAIM in header:
        for mode in ('apply', 'dry run'):
            if any(line.startswith(f'Mode: {mode}') for line in header):
                return mode
    return None


def is_apply(lines):
    return reclaim_mode(lines) == 'apply'


def paths(directory):
    return sorted((path for path in Path(directory).glob('????-??-??*.md') if re.fullmatch(FILENAME, path.name)),
                  key=lambda path: path.stem)


def written(path):
    try:
        moment = datetime.strptime(path.stem[:24], '%Y-%m-%d-%H%M%S-%f')
    except ValueError:
        moment = datetime.strptime(path.stem[:10], '%Y-%m-%d')
    return moment.replace(tzinfo=timezone.utc)


def timestamp(value, where):
    try:
        moment = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        moment = None
    if moment is None or moment.tzinfo is None:
        raise ValueError(f'{where}: "at" must be an ISO timestamp with a time zone, got {value!r}')
    return moment


def log_paths(directory):
    live = directory / 'reclaim-actions.jsonl'
    return sorted(directory.glob('reclaim-actions-*.jsonl.gz')) + ([live] if live.exists() else [])


def action_fields(row, name):
    return (isinstance(row, dict) and row.get('host') == name
            and type(row.get('bytes')) is int and row['bytes'] >= 0
            and all(isinstance(row.get(key), str) for key in ACTION_KEYS if key != 'bytes'))


def read_source(directory, name):
    import fcntl

    with contextlib.ExitStack() as stack:
        lock = directory / 'reclaim-actions.lock'
        if lock.exists():
            fcntl.flock(stack.enter_context(lock.open()), fcntl.LOCK_SH)
        reports = [path for path in paths(directory) if path.is_file() and not path.is_symlink()]
        if not reports:
            return None
        latest = reports[-1]
        text = latest.read_text(encoding='utf-8')
        rows = []
        if is_apply(text.splitlines()):
            visible = set(host_lines(text, name))
            end = written(latest)
            start = written(reports[-2]) if len(reports) > 1 else datetime.min.replace(tzinfo=timezone.utc)
            for path in log_paths(directory):
                if not path.is_file() or path.is_symlink():
                    continue
                if path.suffix == '.gz' and path.name < f'reclaim-actions-{start:%Y%m%dT%H%M%S%fZ}.jsonl.gz':
                    continue
                opener = gzip.open if path.suffix == '.gz' else open
                with opener(path, 'rb') as stream:
                    for line in stream:
                        row = json.loads(line)
                        if not action_fields(row, name) or action_line(row) not in visible:
                            continue
                        at = timestamp(row['at'], 'local action log')
                        if start < at <= end:
                            projected = {key: row[key] for key in ACTION_KEYS}
                            projected.update(action=reported_action(row), at=at.isoformat(), path=row['path'].replace('\n', ' ').replace('\r', ' '),
                                             reason=row['reason'].replace('\n', ' ').replace('\r', ' '))
                            rows.append(projected)
        return latest.name, text, rows


if __name__ == '__main__':
    print(json.dumps(read_source(Path(sys.argv[1]).expanduser(), sys.argv[2])))
