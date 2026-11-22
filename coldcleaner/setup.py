import json
import math
import os
from pathlib import Path
import shutil
import tempfile
import tomllib

from . import rules


def value(item):
    if isinstance(item, dict):
        return '{ ' + ', '.join(f'{json.dumps(key)} = {value(entry)}' for key, entry in item.items()) + ' }'
    if isinstance(item, list):
        return '[' + ', '.join(value(entry) for entry in item) + ']'
    return json.dumps(item, ensure_ascii=False)


def ask(prompt, choices):
    answer = input(prompt).strip()
    if answer and answer not in choices:
        raise ValueError(f'expected {", ".join(choices)} or blank')
    return answer


def configure(path, yes=False):
    path = Path(path)
    original = path.read_bytes()
    rules.load(path)
    if yes:
        print('Current settings retained; cleanup still requires reclaim --apply.')
        return
    data = tomllib.loads(original.decode())
    print('Blank answers retain current settings. No cleanup runs during init.')
    mode = ask('1. Cleanup mode [preview/approve/auto]: ', ('preview', 'approve', 'auto'))
    if mode:
        data['live'] = [] if mode == 'preview' else list(rules.TIERS)
        data['approval'] = list(rules.APPROVAL_TIERS) if mode == 'approve' else []
    for number, key, label in ((2, 'archive_before_delete', 'Archive before deleting'),
                               (3, 'backup_copy_check', 'Verify backup copy')):
        answer = ask(f'{number}. {label} [on/off]: ', ('on', 'off'))
        if answer:
            data[key] = answer
    vault = input('4. Notes vault [off / absolute preservation receipts path]: ').strip()
    if vault:
        data['notes_vault'] = 'off' if vault == 'off' else 'on'
        if vault != 'off':
            data['memory_store'] = vault
    print('Age-only scans children of matching POSIX folders; matching files are skipped. Off removes age-only entries.')
    age = ask('5. Age-only cleanup [off/30/60/90]: ', ('off', '30', '60', '90'))
    if age:
        for host in data['hosts'].values():
            if host['kind'] != 'posix':
                continue
            entries = []
            for entry in host.get('archive', []):
                entry = dict(entry) if isinstance(entry, dict) else {'path': entry}
                if age == 'off':
                    if 'age_days' in entry:
                        continue
                else:
                    entry.pop('days', None)
                    entry['age_days'] = int(age)
                entries.append(entry)
            if 'archive' in host:
                host['archive'] = entries
    wait = input('6. Wait period in days [blank keeps current per-tier waits]: ').strip()
    if wait:
        days = float(wait)
        if not math.isfinite(days) or days < 0:
            raise ValueError('wait period must be a non-negative finite number')
        data['wait_period_days'] = days
    if data == tomllib.loads(original.decode()):
        print('Current settings retained.')
        return
    text = '\n'.join(f'{json.dumps(key)} = {value(item)}' for key, item in data.items() if key != 'hosts') + '\n'
    for name, host in data['hosts'].items():
        text += f'\n[hosts.{json.dumps(name)}]\n'
        text += '\n'.join(f'{json.dumps(key)} = {value(item)}' for key, item in host.items()) + '\n'
    candidate = None
    backup = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + '.', suffix='.new', delete=False) as stream:
            candidate = Path(stream.name)
            stream.write(text.encode())
        rules.load(candidate)
        shutil.copymode(path, candidate)
        if path.read_bytes() != original:
            raise ValueError('rules changed during init; refusing to overwrite')
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + '.', suffix='.bak', delete=False) as stream:
            backup = Path(stream.name)
            stream.write(original)
        os.replace(candidate, path)
    finally:
        if candidate is not None:
            candidate.unlink(missing_ok=True)
    print(f'Saved {path}; original backed up to {backup}.')
