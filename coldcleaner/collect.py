import json
import re
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from . import hosts, locking, metrics, reclaim, report_files


def directories(config):
    base = Path(config['report_dir']) / 'fleet' / 'collected'
    return {name: base / name for name in config.get('collect_hosts', ())}


def read(config, name):
    command = shlex.join(['python3', '-', config['hosts'][name]['report_dir'], name])
    source = Path(report_files.__file__).read_bytes()
    result = hosts.run(hosts.HOSTS[name], command, stdin_bytes=source, timeout=60)
    payload = json.loads(result.stdout)
    if payload is None:
        return None
    filename, text, rows = payload
    if (not isinstance(filename, str) or not re.fullmatch(report_files.FILENAME, filename)
            or not isinstance(text, str) or not report_files.host_lines(text, name) or not isinstance(rows, list)):
        raise ValueError('invalid local report')
    visible = set(report_files.host_lines(text, name))
    if (rows and not report_files.is_apply(text.splitlines())) or any(
            not report_files.action_fields(row, name) or set(row) != set(report_files.ACTION_KEYS)
            or any('\n' in row[key] or '\r' in row[key] for key in ('tier', 'action', 'path', 'reason'))
            or report_files.action_line(row) not in visible for row in rows):
        raise ValueError('invalid local action rows')
    written = metrics.written(Path(filename))
    for row in rows:
        at = metrics.timestamp(row['at'], 'local action log')
        if at > written:
            raise ValueError('action row is newer than its report')
        row['at'] = at.isoformat()
    return filename, text, rows


def save(config, target, payload):
    filename, text, rows = payload
    destination = target / filename
    directory = Path(config['report_dir'])
    target.mkdir(parents=True, exist_ok=True)
    with (directory / 'reclaim-actions.lock').open('a') as lock:
        locking.lock(lock)
        if destination.exists():
            return
        if rows:
            known = {(row['at'], report_files.action_line(row)) for row in metrics.read_actions(directory)
                     if row['host'] == rows[0]['host']}
            for row in rows:
                identity = metrics.timestamp(row['at'], 'local action log'), report_files.action_line(row)
                if identity not in known:
                    reclaim.append_action(directory, row, config.get('actions_log_mb', 10), datetime.now(timezone.utc))
                    known.add(identity)
        temporary = destination.with_suffix('.tmp')
        try:
            temporary.write_text(text, encoding='utf-8')
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)


def run(config):
    errors = []
    for name, directory in directories(config).items():
        try:
            payload = read(config, name)
            if payload is None:
                errors.append(f'{name}: no local report to collect')
            else:
                save(config, directory, payload)
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            errors.append(f'{name}: local report collection failed')
    return errors
