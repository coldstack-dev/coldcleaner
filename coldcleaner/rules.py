import fnmatch
import hashlib
import json
import math
import os
import re
import tomllib
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath

from . import hosts

TIERS = ('worktree', 'clone', 'archive', 'rebuild')
REGENERABLE_NAMES = ('node_modules', '.venv', 'venv', 'target', 'dist', 'build', '__pycache__', '.cache', '.next')
REMOVED_KEYS = ('hard_pct', 'project_idle_days', 'compact_idle_days', 'compact_weekday', 'nas_cap_gb', 'regenerable_paths')
REMOVED_TIERS = ('github', 'project', 'compact')
def default_path(checkout=Path(__file__).resolve().parent.parent):
    if (checkout / 'rules.toml').is_file():
        return checkout / 'rules.toml'
    return Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'coldcleaner' / 'rules.toml'


DEFAULT_PATH = default_path()


TOP_LEVEL_KEYS = frozenset({
    'alert_pct', 'worktree_idle_days', 'archive_idle_days', 'abandoned_idle_days',
    'nas_root', 'local_archive_mount', 'report_dir', 'live', 'approval',
    'already_compressed_extensions', 'hosts', 'reclaim_hosts', 'collect_hosts', 'agent_worktree_hosts', 'actions_log_mb', 'manual_notes',
    'max_items_per_run', 'max_gib_per_run', 'attention_note', 'memory_store',
    'archive_before_delete', 'backup_copy_check', 'notes_vault', 'wait_period_days', 'quarantine_days',
})
REQUIRED_KEYS = (
    'alert_pct', 'worktree_idle_days', 'archive_idle_days', 'live', 'nas_root', 'report_dir',
    'already_compressed_extensions', 'hosts',
)
LOCAL_POLICY_KEYS = {'report_dir', 'archive_before_delete', 'live'}
HOST_KEYS = frozenset({'roots', 'archive', 'shared_roots', 'protected', 'exclude', 'kind', 'ssh', 'distro',
                       'max_items_per_run', 'max_gib_per_run', 'managed_bytes_target'} | LOCAL_POLICY_KEYS)
ARCHIVE_ENTRY_KEYS = ('path', 'days', 'backup', 'exclude', 'category', 'approval', 'preservation', 'age_days', 'children')
APPROVAL_TIERS = ('worktree', 'clone', 'archive', 'rebuild')
BACKUPS = ('nas', 'none-if-regenerable')
CATEGORIES = ('scratch', 'test-output', 'artifact')
PRESERVATION = ('sha256', 'summary')
ABANDONED_IDLE_DAYS = 30
LIMIT_KEYS = {'max_items_per_run': 200, 'max_gib_per_run': 100}
PERSONAL_FOLDERS = ('Documents', 'Desktop', 'Pictures', 'Library', 'iCloud Drive', 'iCloudDrive', 'Google Drive', 'OneDrive*')
POSIX_PROTECTED = ('/etc', '/usr', '/System', *('~/' + name for name in PERSONAL_FOLDERS))
WINDOWS_SYSTEM = ('C:\\Windows', '%SYSTEMROOT%', '%WINDIR%')
WINDOWS_PROTECTED = ('C:\\Program Files*', '%PROGRAMFILES%', '%PROGRAMFILES(X86)%', '%PROGRAMW6432%',
                     '%ONEDRIVE%', '%ONEDRIVECONSUMER%', '%ONEDRIVECOMMERCIAL%',
                     *('%USERPROFILE%\\' + name for name in PERSONAL_FOLDERS))
WINDOWS_TEMP_FOLDERS = (
    '%TEMP%', '%TMP%', '%LOCALAPPDATA%\\TEMP', '%USERPROFILE%\\APPDATA\\LOCAL\\TEMP',
    'C:\\WINDOWS\\TEMP', '%SYSTEMROOT%\\TEMP', '%WINDIR%\\TEMP',
)


def is_windows_temp(path):
    normal = path.replace('/', '\\').upper()
    return any(normal == folder or normal.startswith(folder + '\\') for folder in WINDOWS_TEMP_FOLDERS)


class LocalHostError(ValueError):
    pass


def load(path=DEFAULT_PATH, local=None, report_dir=None):
    raw = Path(path).read_bytes()
    data = tomllib.loads(raw.decode())
    reject_cache_options(data)
    reject_legacy_options(data)
    unknown = set(data) - TOP_LEVEL_KEYS
    if unknown:
        raise ValueError(f'unknown rules option: {sorted(unknown)[0]}; known options: {", ".join(sorted(TOP_LEVEL_KEYS))}')
    missing = [key for key in REQUIRED_KEYS if key not in data
               and not (key == 'nas_root' and data.get('archive_before_delete') == 'off' and not data.get('local_archive_mount'))]
    if missing:
        raise ValueError(f'missing required key {missing[0]}')
    host_rules = data['hosts']
    if not isinstance(host_rules, dict):
        raise ValueError(f'hosts must be a table, got {host_rules!r}')
    local_policy = {}
    for name, config in host_rules.items():
        if not isinstance(config, dict):
            raise ValueError(f'{name} must be a table, got {config!r}')
        keys = LOCAL_POLICY_KEYS & config.keys()
        if not keys:
            continue
        if (keys != LOCAL_POLICY_KEYS or config.get('kind') != 'posix'
                or config['archive_before_delete'] != 'off' or not git_only(config['live'])):
            raise ValueError(f'{name}: local policy needs a POSIX host, report_dir, archive_before_delete = "off" '
                             'and live tiers limited to worktree and clone')
        output_path(f'{name}.report_dir', config['report_dir'])
        if name == local:
            local_policy = {key: config[key] for key in keys}
    if type(data.get('alert_pct')) is not int or not 0 < data['alert_pct'] <= 100:
        raise ValueError(f"alert_pct must be an integer from 1 through 100, got {data.get('alert_pct')!r}")
    data.setdefault('abandoned_idle_days', ABANDONED_IDLE_DAYS)
    for key in ('worktree_idle_days', 'archive_idle_days', 'abandoned_idle_days'):
        value = data.get(key)
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError(f'{key} must be a non-negative finite number, got {value!r}')
    for key in ('archive_before_delete', 'backup_copy_check', 'notes_vault'):
        if key in data and data[key] not in ('on', 'off'):
            raise ValueError(f'{key} must be on or off')
    positive_limit('quarantine_days', data.setdefault('quarantine_days', 7))
    if 'wait_period_days' in data:
        value = data['wait_period_days']
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError('wait_period_days must be a non-negative finite number')
    if 'actions_log_mb' in data and (type(data['actions_log_mb']) is not int or data['actions_log_mb'] < 1):
        raise ValueError(f"actions_log_mb must be a positive integer, got {data['actions_log_mb']!r}")
    for key in LIMIT_KEYS:
        if key in data:
            positive_limit(key, data[key])
    live = data.get('live')
    if not isinstance(live, list):
        raise ValueError(f'live must be an array, got {live!r}')
    for index, tier in enumerate(live):
        if tier not in TIERS:
            raise ValueError(f'live[{index}]: unknown tier: {tier!r}; known tiers: {", ".join(TIERS)}')
        if tier in live[:index]:
            raise ValueError(f'live[{index}]: repeated tier: {tier!r}')
    approval = data.setdefault('approval', [])
    if not isinstance(approval, list):
        raise ValueError(f'approval must be an array, got {approval!r}')
    for index, tier in enumerate(approval):
        if tier not in APPROVAL_TIERS:
            raise ValueError(f'approval[{index}]: unknown tier: {tier!r}; known tiers: {", ".join(APPROVAL_TIERS)}')
        if tier in approval[:index]:
            raise ValueError(f'approval[{index}]: repeated tier: {tier!r}')
    if local_policy:
        data.update(local_policy)
        for key in ('nas_root', 'local_archive_mount', 'attention_note', 'memory_store'):
            data.pop(key, None)
    if report_dir is not None:
        data['report_dir'] = str(report_dir)
    output_keys = [key for key in ('nas_root', 'report_dir', 'attention_note', 'memory_store') if key in data]
    output_paths = {key: data.get(key) for key in output_keys}
    for key in output_keys:
        data[key] = output_path(key, output_paths[key])
    mount = data.get('local_archive_mount', '')
    if mount != '':
        if os.name == 'nt':
            raise ValueError('local_archive_mount needs a POSIX controller')
        if not isinstance(mount, str) or not Path(mount).is_absolute() or any(c in mount for c in '*?[') or has_control(mount) \
                or '..' in mount.replace('\\', '/').split('/') or root_or_home(mount):
            raise ValueError(f'local_archive_mount must be an absolute mount point, not a root, home or glob path, got {mount!r}')
        if not PurePosixPath(data['nas_root']).is_relative_to(PurePosixPath(mount)):
            raise ValueError(f"nas_root must be inside local_archive_mount, got {output_paths['nas_root']!r} outside {mount!r}")
    notes = data.get('manual_notes', [])
    if not isinstance(notes, list):
        raise ValueError(f'manual_notes must be an array of strings, got {notes!r}')
    for index, note in enumerate(notes):
        if not isinstance(note, str) or not note.strip() or has_control(note):
            raise ValueError(f'manual_notes[{index}]: not a nonempty single-line string: {note!r}')
        if note in notes[:index]:
            raise ValueError(f'manual_notes[{index}]: repeated note: {note!r}')
    extensions = data.get('already_compressed_extensions')
    if not isinstance(extensions, list):
        raise ValueError(f'already_compressed_extensions must be an array, got {extensions!r}')
    seen_extensions = set()
    for index, extension in enumerate(extensions):
        if (not isinstance(extension, str) or not extension.startswith('.') or len(extension) < 2
                or any(c.isspace() or c in '/\\*?[' for c in extension)):
            raise ValueError(f"already_compressed_extensions[{index}]: not a file extension like '.zip': {extension!r}")
        if extension.lower() in seen_extensions:
            raise ValueError(f'already_compressed_extensions[{index}]: repeated extension: {extension!r}')
        seen_extensions.add(extension.lower())
    registry = {}
    local_kind = 'powershell' if os.name == 'nt' else 'posix'
    for name, config in host_rules.items():
        unknown = set(config) - HOST_KEYS
        if unknown:
            raise ValueError(f'unknown host option: {name}.{sorted(unknown)[0]}; known options: {", ".join(sorted(HOST_KEYS))}')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name):
            raise ValueError(f'invalid host name {name!r}: use letters, digits, dot, dash or underscore, starting with a letter or digit')
        if 'kind' not in config:
            raise ValueError(f'{name}.kind is missing: rules files from before configured hosts must add kind = "posix", '
                             f'"powershell" or "wsl" to every host table, and ssh = "<destination>" to every remote host; '
                             f'a table without ssh runs on this machine')
        kind = config['kind']
        if kind not in ('posix', 'powershell', 'wsl'):
            raise ValueError(f'{name}.kind must be posix, powershell or wsl, got {kind!r}')
        if kind not in ('posix', local_kind) and 'ssh' not in config:
            raise ValueError(f'{name}.ssh is required for {kind} hosts: the controller runs on Linux or macOS')
        if os.name == 'nt' and kind == 'posix' and 'ssh' not in config:
            raise ValueError(f'{name}.ssh is required for posix hosts on a Windows controller')
        for key in ('ssh', 'distro'):
            if key in config and (not isinstance(config[key], str) or not config[key].strip()):
                raise ValueError(f'{name}.{key} must be a nonempty string, got {config[key]!r}')
        for key in (*LIMIT_KEYS, 'managed_bytes_target'):
            if key in config:
                positive_limit(f'{name}.{key}', config[key])
        registry[name] = hosts.Host(name, kind, None if name == local else config.get('ssh'), config.get('distro'))
        for key in ('roots', 'archive', 'shared_roots', 'protected', 'exclude'):
            paths = config.get(key, [])
            if not isinstance(paths, list):
                raise ValueError(f'{name}.{key} must be an array, got {paths!r}')
            if key == 'archive':
                for index, entry in enumerate(paths):
                    if isinstance(entry, dict):
                        check_archive_entry(f'{name}.archive[{index}]', entry)
                        if 'age_days' in entry and kind != 'posix':
                            raise ValueError(f'{name}.archive[{index}].age_days needs a posix host')
                paths = archive_patterns(config)
            for index, path in enumerate(paths):
                if not valid_path(path):
                    raise ValueError(f'{name}.{key}[{index}]: not an explicit absolute or home path: {path!r}')
                if key in ('shared_roots', 'protected') and any(char in path for char in '*?['):
                    raise ValueError(f'{name}.{key}[{index}]: {key} must not contain globs')
                if path_key(path) in [path_key(earlier) for earlier in paths[:index]]:
                    raise ValueError(f'{name}.{key}[{index}]: repeated path: {path!r}')
        for key in ('roots', 'archive'):
            for index, path in enumerate(archive_patterns(config) if key == 'archive' else config.get(key, [])):
                location = protected_location(path, kind, config.get('protected', []))
                if location:
                    raise ValueError(f'{name}.{key}[{index}]: overlaps protected location {location!r}, got {path!r}')
    if local is not None and (local not in registry or registry[local].kind != local_kind):
        raise LocalHostError(f'--local needs a configured {local_kind} host, got {local!r}; known hosts: {", ".join(sorted(registry))}')
    if local_kind == 'powershell':
        local_names = [name for name, host in registry.items() if host.ssh is None]
        if len(local_names) > 1:
            raise ValueError(f'a Windows controller can run only one local PowerShell host, got {", ".join(local_names)}')
    reclaim_hosts = data.get('reclaim_hosts', [name for name, host in registry.items() if host.kind != 'wsl'])
    if not isinstance(reclaim_hosts, list):
        raise ValueError(f'reclaim_hosts must be an array, got {reclaim_hosts!r}')
    for index, name in enumerate(reclaim_hosts):
        if not isinstance(name, str) or name not in registry:
            raise ValueError(f'reclaim_hosts[{index}]: unknown host: {name!r}; known hosts: {", ".join(sorted(registry))}')
    agent_hosts = data.get('agent_worktree_hosts', [])
    if not isinstance(agent_hosts, list):
        raise ValueError('agent_worktree_hosts must be an array of host names')
    for index, name in enumerate(agent_hosts):
        if not isinstance(name, str) or name not in registry or registry[name].kind != 'posix':
            raise ValueError(f'agent_worktree_hosts[{index}]: expected a configured POSIX host, got {name!r}')
        if name in agent_hosts[:index]:
            raise ValueError(f'agent_worktree_hosts[{index}]: repeated host {name!r}')
    collect_hosts = data.get('collect_hosts', [])
    if not isinstance(collect_hosts, list):
        raise ValueError('collect_hosts must be an array of host names')
    for index, name in enumerate(collect_hosts):
        if (not isinstance(name, str) or name not in registry or not host_rules[name].get('ssh')
                or registry[name].kind != 'posix' or 'report_dir' not in host_rules[name]):
            raise ValueError(f'collect_hosts[{index}]: expected a remote POSIX host with a local report_dir, got {name!r}')
        if name in collect_hosts[:index]:
            raise ValueError(f'collect_hosts[{index}]: repeated host {name!r}')
    data['reclaim_hosts'] = [name for name in reclaim_hosts if name not in collect_hosts]
    data['collect_hosts'] = [] if local_policy else collect_hosts
    for name, config in host_rules.items():
        if registry[name].ssh is not None:
            continue
        for tier in ('roots', 'archive'):
            for index, path in enumerate(archive_patterns(config) if tier == 'archive' else config.get(tier, [])):
                windows = registry[name].kind == 'powershell'
                cleanup = output_parts(path, windows)
                for key in output_keys:
                    output = output_parts(data[key], windows)
                    if (len(cleanup) <= len(output) or key == 'memory_store') and all(
                            fnmatch.fnmatchcase(part, pattern)
                            and (not part.startswith('.') or pattern.startswith('.'))
                            for part, pattern in zip(output, cleanup)):
                        raise ValueError(f'{name}.{tier}[{index}]: would clean up {key} {output_paths[key]!r}, got {path!r}')
    hosts.HOSTS.clear()
    hosts.HOSTS.update(registry)
    policy = raw + b'\0' + local.encode() if local_policy else raw
    data['rules_sha256'] = hashlib.sha256(policy).hexdigest()
    return data


def git_only(live):
    return (isinstance(live, list) and 1 <= len(live) <= 2
            and all(tier in ('worktree', 'clone') for tier in live) and len(set(live)) == len(live))


def output_path(key, value):
    expanded = str(Path(value).expanduser()) if isinstance(value, str) else value
    if not isinstance(expanded, str) or not Path(expanded).is_absolute():
        raise ValueError(f'{key} must be absolute, got {expanded!r}')
    if any(c in expanded for c in '*?['):
        raise ValueError(f'{key} must not contain glob characters, got {value!r}')
    if has_control(expanded):
        raise ValueError(f'{key} must not contain control characters, got {value!r}')
    if expanded != expanded.strip():
        raise ValueError(f'{key} must not start or end with whitespace, got {value!r}')
    if '..' in expanded.replace('\\', '/').split('/'):
        raise ValueError(f"{key} must not contain '..' segments, got {value!r}")
    path = Path(expanded)
    if root_or_home(expanded) or (os.name == 'nt' and path in (Path.home(), Path(path.anchor))):
        raise ValueError(f'{key} must not be a filesystem root or the home folder, got {value!r}')
    return expanded


def output_parts(path, windows):
    if windows:
        expanded = PureWindowsPath(os.path.expandvars(os.path.expanduser(path)))
        return tuple(part.casefold() for part in expanded.parts)
    return PurePosixPath(Path(path).expanduser()).parts


def archive_patterns(host_rules):
    return [entry['path'] if isinstance(entry, dict) else entry for entry in host_rules.get('archive', [])]


def archive_entry(host_rules, pattern):
    entry = next((entry for entry in host_rules.get('archive', [])
                  if isinstance(entry, dict) and entry['path'] == pattern), {})
    return dict(days=entry.get('age_days', entry.get('days')), backup=entry.get('backup', 'nas'),
                exclude=[*host_rules.get('exclude', []), *entry.get('exclude', [])], category=entry.get('category'),
                approval=entry.get('approval', False),
                preservation=entry.get('preservation', PRESERVATION[0]) if entry.get('category') == 'artifact' else None)


def check_archive_entry(where, entry):
    unknown = set(entry) - set(ARCHIVE_ENTRY_KEYS)
    if unknown:
        raise ValueError(f'unknown archive option: {where}.{sorted(unknown)[0]}; known options: {", ".join(ARCHIVE_ENTRY_KEYS)}')
    if 'path' not in entry:
        raise ValueError(f'{where}.path is missing')
    days = entry.get('days', 0)
    if type(days) not in (int, float) or not math.isfinite(days) or days < 0:
        raise ValueError(f'{where}.days must be a non-negative finite number, got {days!r}')
    if 'age_days' in entry:
        if type(entry['age_days']) is not int or entry['age_days'] not in (30, 60, 90):
            raise ValueError(f'{where}.age_days must be 30, 60 or 90')
        if 'days' in entry:
            raise ValueError(f'{where}: use age_days or days, not both')
    backup = entry.get('backup', 'nas')
    if backup not in BACKUPS:
        raise ValueError(f'{where}.backup must be one of {", ".join(BACKUPS)}, got {backup!r}')
    if backup == 'none-if-regenerable' and not (isinstance(entry['path'], str) and any(
            PurePosixPath(entry['path'].replace('\\', '/')).match(name) for name in REGENERABLE_NAMES)):
        raise ValueError(f'{where}.backup none-if-regenerable needs a path ending in one of {", ".join(REGENERABLE_NAMES)}, got {entry["path"]!r}')
    if entry.get('category', CATEGORIES[0]) not in CATEGORIES:
        raise ValueError(f'{where}.category must be one of {", ".join(CATEGORIES)}, got {entry["category"]!r}')
    if 'preservation' in entry and (entry.get('category') != 'artifact' or entry['preservation'] not in PRESERVATION):
        raise ValueError(f'{where}.preservation must be one of {", ".join(PRESERVATION)} on an artifact entry, got {entry["preservation"]!r}')
    if type(entry.get('approval', False)) is not bool:
        raise ValueError(f'{where}.approval must be true or false, got {entry["approval"]!r}')
    if type(entry.get('children', False)) is not bool:
        raise ValueError(f'{where}.children must be true or false, got {entry["children"]!r}')
    exclude = entry.get('exclude', [])
    if not isinstance(exclude, list):
        raise ValueError(f'{where}.exclude must be an array, got {exclude!r}')
    for index, path in enumerate(exclude):
        if not valid_path(path):
            raise ValueError(f'{where}.exclude[{index}]: not an explicit absolute or home path: {path!r}')


def preservation_receipt(config, host, path, policy):
    if 'memory_store' not in config:
        raise ValueError('no preservation receipt: memory_store is not configured')
    name = hashlib.sha256(f'{host}:{path}'.encode()).hexdigest() + '.json'
    try:
        receipt = json.loads((Path(config['memory_store']) / name).read_text(encoding='utf-8'))
    except FileNotFoundError:
        raise ValueError(f'no preservation receipt {name} in {config["memory_store"]}') from None
    except (OSError, ValueError):
        raise ValueError(f'invalid preservation receipt {name}') from None
    fields = {'schema_version', 'host', 'path', 'sha256', 'destination', 'verified_at'}
    if isinstance(receipt, dict) and (receipt.get('schema_version') == 1 or 'summary' in receipt and 'sha256' not in receipt):
        raise ValueError('not eligible: legacy or summary-only preservation receipt')
    if not isinstance(receipt, dict) or set(receipt) != fields \
            or type(receipt['schema_version']) is not int or receipt['schema_version'] != 2 \
            or receipt['host'] != host or receipt['path'] != path \
            or not isinstance(receipt['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', receipt['sha256']) \
            or not isinstance(receipt['destination'], str) or not isinstance(receipt['verified_at'], str) \
            or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', receipt['verified_at']):
        raise ValueError(f'invalid preservation receipt {name} for {policy} policy')
    try:
        datetime.strptime(receipt['verified_at'], '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        raise ValueError(f'invalid preservation receipt {name}: verified_at') from None
    return receipt


def positive_limit(key, value):
    if type(value) is not int or value < 1:
        raise ValueError(f'{key} must be a positive integer, got {value!r}')


def reject_cache_options(data):
    found = ['cache_idle_days'] if 'cache_idle_days' in data else []
    if isinstance(data.get('live'), list) and 'cache' in data['live']:
        found.append(f"live[{data['live'].index('cache')}]")
    for name, config in (data.get('hosts') if isinstance(data.get('hosts'), dict) else {}).items():
        if isinstance(config, dict):
            found.extend(f'{name}.{key}' for key in ('cache', 'cache_tools') if key in config)
    if found:
        raise ValueError(f'{found[0]}: removed; caches are out of scope')


def reject_legacy_options(data):
    found = [key for key in REMOVED_KEYS if key in data]
    if isinstance(data.get('live'), list):
        found.extend(f'live[{index}]' for index, tier in enumerate(data['live']) if tier in REMOVED_TIERS)
    for name, config in (data.get('hosts') if isinstance(data.get('hosts'), dict) else {}).items():
        if isinstance(config, dict) and 'compact' in config:
            found.append(f'{name}.compact')
    if found:
        raise ValueError(f"removed with the legacy run tiers; delete {', '.join(found)}")


def protected_location(path, kind, extra=()):
    builtin = WINDOWS_PROTECTED if kind == 'powershell' else POSIX_PROTECTED
    if kind == 'powershell' and not is_windows_temp(path):
        builtin += WINDOWS_SYSTEM
    for location in (*builtin, *extra):
        for cleanup in home_aliases(path_key(path)):
            for protected in home_aliases(path_key(location)):
                if cleanup[0] == protected[0] and all(
                        fnmatch.fnmatchcase(left, right) or fnmatch.fnmatchcase(right, left)
                        for left, right in zip(map(str.casefold, cleanup[1:]), map(str.casefold, protected[1:]))):
                    return location
    return None


def home_aliases(key):
    if key[:2] == (False, '~'):
        return key, (True, 'home', '*', *key[2:]), (True, 'Users', '*', *key[2:])
    if key[:2] == (False, '%userprofile%'):
        return key, (False, 'c:', 'users', '*', *key[2:])
    return key,



def has_control(path):
    return any(ord(c) < 32 or c == '\x7f' for c in path)


def plain(path):
    return not has_control(path) and path == path.strip()


def path_key(path):
    windows = path.startswith('%') or path[1:3] == ':\\'
    segments = path.replace('\\', '/').casefold().split('/') if windows else path.split('/')
    return path.startswith('/'), *(s for s in segments if s not in ('', '.'))


def root_or_home(path):
    normalized = PurePosixPath(path.replace('\\', '/'))
    parts = normalized.parts
    return (str(normalized) in ('.', '/', '//', '~', str(Path.home()))
            or str(normalized).upper() == '%USERPROFILE%'
            or len(parts) == 1 and len(parts[0]) == 2
            and parts[0][0].isascii() and parts[0][0].isalpha() and parts[0][1] == ':')


def valid_path(path):
    if not isinstance(path, str):
        return False
    if root_or_home(path):
        return False
    return path not in ('', '/', '~/', 'C:\\', 'c:\\') and plain(path) and '..' not in path.replace('\\', '/').split('/') and (
        path.startswith(('/', '~/', '%')) or (len(path) > 2 and path[1:3] == ':\\'))

