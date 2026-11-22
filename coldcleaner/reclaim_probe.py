"""Stdlib probe sent to a cleanup host; every operation uses an explicit path."""
import hashlib
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time


def sha256_hex(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
    return digest.hexdigest()


def windows_change_time(kernel, handle, path):
    import ctypes
    from ctypes import wintypes

    class FileBasicInfo(ctypes.Structure):
        _fields_ = [('creation', ctypes.c_longlong), ('access', ctypes.c_longlong),
                    ('write', ctypes.c_longlong), ('change', ctypes.c_longlong),
                    ('attributes', wintypes.DWORD)]

    query = kernel.GetFileInformationByHandleEx
    query.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    query.restype = wintypes.BOOL
    info = FileBasicInfo()
    if not query(handle, 0, ctypes.byref(info), ctypes.sizeof(info)) or info.change <= 0:
        raise ValueError('Windows change time unavailable: ' + str(path))
    return info.change


def windows_file_safety(path, approval=False):
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ValueError('Windows path is open or unreadable: ' + str(path))
    try:
        change = windows_change_time(kernel, handle, path) if approval else None
        if not os.path.isdir(path):
            ntdll = ctypes.WinDLL('ntdll')
            ntdll.NtQueryInformationFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                                     ctypes.c_ulong, ctypes.c_int]
            users = ctypes.create_string_buffer(65536)
            status = ntdll.NtQueryInformationFile(handle, (ctypes.c_void_p * 2)(), users, len(users), 47)
            if status or ctypes.c_ulong.from_buffer(users).value:
                raise ValueError('Windows file is mapped by a running program: ' + str(path))
    finally:
        kernel.CloseHandle(handle)
    if not os.path.isdir(path):
        handle = kernel.CreateFileW(str(path), 0x2, 7, None, 3, 0, None)
        if handle != ctypes.c_void_p(-1).value:
            kernel.CloseHandle(handle)
        elif ctypes.get_last_error() == 32:
            raise ValueError('Windows file is mapped by a running program or driver: ' + str(path))
    class Streams(ctypes.Structure):
        _fields_ = [('size', ctypes.c_longlong), ('name', wintypes.WCHAR * 296)]
    kernel.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(Streams), wintypes.DWORD]
    kernel.FindFirstStreamW.restype = wintypes.HANDLE
    kernel.FindNextStreamW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Streams)]
    kernel.FindClose.argtypes = [wintypes.HANDLE]
    stream = Streams()
    handle = kernel.FindFirstStreamW(str(path), 0, ctypes.byref(stream), 0)
    if handle == ctypes.c_void_p(-1).value:
        if ctypes.get_last_error() != 38:
            raise ValueError('NTFS stream inventory incomplete: ' + str(path))
        return change
    try:
        while True:
            if stream.name != '::$DATA':
                raise ValueError('NTFS alternate streams require preservation: ' + str(path))
            if not kernel.FindNextStreamW(handle, ctypes.byref(stream)):
                if ctypes.get_last_error() != 38:
                    raise ValueError('NTFS stream inventory incomplete: ' + str(path))
                break
    finally:
        kernel.FindClose(handle)
    return change


def require_ntfs(path):
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    query = kernel.GetVolumeInformationW
    query.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                      wintypes.LPDWORD, wintypes.LPDWORD, wintypes.LPDWORD,
                      wintypes.LPWSTR, wintypes.DWORD]
    query.restype = wintypes.BOOL
    filesystem = ctypes.create_unicode_buffer(32)
    if not query(path.anchor, None, 0, None, None, None, filesystem, len(filesystem)) or filesystem.value != 'NTFS':
        raise ValueError('Windows approval needs an NTFS source: ' + str(path))


def git(path, *args, check=True):
    result = subprocess.run(['git', '-C', str(path), *args], capture_output=True, text=True,
                            env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'GIT_TERMINAL_PROMPT': '0',
                                 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1'})
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Git check failed')
    return result.stdout.strip() if check else result


def real_key(path):
    fold = str.casefold if sys.platform == 'darwin' else os.path.normcase
    return fold(os.path.realpath(path))


def overlap(a, b):
    return overlap_keys(real_key(a), real_key(b))


def overlap_keys(a, b):
    try:
        return os.path.commonpath((a, b)) in (a, b)
    except ValueError:
        return False


def contains_key(outer, inner):
    return os.path.commonpath((outer, inner)) == outer


def broad_folder(reference, key, broad):
    for item in broad:
        if real_key(item) == key:
            try:
                if os.path.samefile(reference, item):
                    return True
            except OSError:
                pass
    return False


def contained(path, root):
    root = os.path.normcase(os.path.abspath(os.path.expandvars(os.path.expanduser(root))))
    return Path(os.path.normcase(os.path.abspath(path))).is_relative_to(root)


def threads():
    root = Path.home() / '.t3/userdata'
    database = root / 'statev2.sqlite'
    if not root.exists():
        return None
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=10)) as db:
        rows = db.execute('''SELECT t.payload_json, t.archived_at, EXISTS
              (SELECT 1 FROM orchestration_v2_projection_runs r WHERE r.thread_id=t.thread_id
               AND r.status IN ('running','waiting')) FROM orchestration_v2_projection_threads t
            WHERE t.deleted_at IS NULL''')
        paths = []
        for text, archived, running in rows:
            row = json.loads(text)
            settled = row.get('settledOverride') == 'settled' or (
                not row.get('settledOverride') and
                (row.get('settledAt') or '') > (row.get('unsettledAt') or ''))
            if running or row.get('pinnedAt') or row.get('pinOrderKey') is not None or (
                    not (row.get('archivedAt') or archived) and not settled):
                if row.get('worktreePath'):
                    paths.append(row['worktreePath'])
                elif row.get('projectId'):
                    project = db.execute('SELECT workspace_root FROM projection_projects WHERE project_id=?',
                                         (row['projectId'],)).fetchone()
                    if project:
                        paths.append(project[0])
        return paths


def codex_threads():
    root = Path.home() / '.codex'
    if not root.exists():
        return None
    databases = sorted(root.glob('state_*.sqlite'), key=lambda database: int(database.stem.removeprefix('state_')))
    if not databases:
        raise ValueError('no state_*.sqlite in ' + str(root))
    with closing(sqlite3.connect(databases[-1].as_uri() + '?mode=ro', uri=True, timeout=10)) as db:
        rows = db.execute('SELECT cwd, MAX(updated_at) FROM threads WHERE archived = 0 GROUP BY cwd').fetchall()
    broad = {os.path.normcase(str(Path.home())), os.path.normcase(os.path.abspath(os.sep))}
    if not all(isinstance(cwd, str) and isinstance(updated, int) for cwd, updated in rows):
        raise ValueError('unexpected threads.cwd or threads.updated_at type')
    return [(cwd, updated) for cwd, updated in rows if os.path.normcase(os.path.abspath(cwd)) not in broad]


def raise_error(error):
    raise error


def unique_keys(pairs):
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError('duplicate key')
    return dict(pairs)


def record_cwds(value, session, parents=()):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == 'cwd' and isinstance(item, str):
                yield item
            elif key == 'cwd' and not (parents == ('input_schema', 'properties') and isinstance(item, dict)):
                raise ValueError('unexpected cwd in ' + str(session))
            else:
                yield from record_cwds(item, session, (parents + (key,))[-2:])
    elif isinstance(value, list):
        for item in value:
            yield from record_cwds(item, session)


def claude_cwds(content, session):
    lines = content.split(b'\n')
    if lines[-1] and not lines[-1].strip(b'\0') and any(line.strip() for line in lines[:-1]):
        lines.pop()
    for line in lines:
        if line.strip():
            try:
                record = json.loads(line, object_pairs_hook=unique_keys)
            except ValueError:
                raise ValueError('unexpected cwd in ' + str(session)) from None
            yield from record_cwds(record, session)


def windows_cwd(cwd):
    drive = re.fullmatch(r'/mnt/([A-Za-z])(/.*)?', cwd)
    return drive[1].upper() + ':\\' + (drive[2] or '').strip('/').replace('/', '\\') if drive else cwd


def claude_threads(since=None):
    root = Path.home() / '.claude' / 'projects'
    if not os.path.lexists(root):
        return None
    latest = {}
    for directory, folders, names in os.walk(root, onerror=raise_error):
        for name in folders + names:
            if os.path.islink(os.path.join(directory, name)):
                raise ValueError('symlink in Claude Code sessions: ' + os.path.join(directory, name))
        for name in names:
            if not name.endswith('.jsonl'):
                continue
            session = Path(directory) / name
            try:
                updated = session.stat().st_mtime
                if since is not None and updated <= since:
                    continue
                content = session.read_bytes()
            except FileNotFoundError:
                continue
            for cwd in set(claude_cwds(content, session)):
                cwd = windows_cwd(cwd) if os.name == 'nt' and cwd.startswith('/') else cwd
                if '\0' in cwd or not os.path.isabs(cwd) and not (os.name == 'nt' and cwd.startswith('/')):
                    raise ValueError('unexpected cwd in ' + str(session))
                latest[cwd] = max(latest.get(cwd, updated), updated)
    broad = {os.path.normcase(str(Path.home())), os.path.normcase(os.path.abspath(os.sep))}
    return [(cwd, updated) for cwd, updated in latest.items() if os.path.normcase(os.path.abspath(cwd)) not in broad]


def t3_threads():
    found = threads()
    return None if found is None else [(path, None) for path in found]


def workspaces(since=None):
    found, notes, blocked = [], [], []
    for name, detect in (('T3', t3_threads), ('Codex', codex_threads), ('Claude Code', lambda: claude_threads(since))):
        try:
            result = detect()
        except Exception as error:
            blocked.append(f'IN USE: {name} state unreadable, protecting every candidate: {type(error).__name__}: {error}')
            continue
        if result is None:
            notes.append(f'{name} not installed')
        else:
            found.extend([name, path, updated] for path, updated in result)
    return dict(threads=found, notes=notes, blocked=blocked)


def windows_arguments(command):
    import ctypes
    from ctypes import wintypes
    shell = ctypes.WinDLL('shell32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
    kernel.LocalFree.argtypes = [wintypes.LPVOID]
    count = ctypes.c_int()
    arguments = shell.CommandLineToArgvW(command, ctypes.byref(count))
    if not arguments:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return [arguments[index] for index in range(count.value)]
    finally:
        kernel.LocalFree(arguments)


def windows_paths(arguments):
    return [path for argument in arguments for path in re.findall(r'''[A-Za-z]:[\\/][^\r\n<>"'|;,]*''', argument)]


def exited(pid):
    import ctypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x1000, 0, pid)
    if not handle:
        return ctypes.get_last_error() == 87
    try:
        code = ctypes.c_ulong()
        return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value != 259
    finally:
        kernel.CloseHandle(handle)


def drivers():
    import ctypes
    from ctypes import wintypes
    psapi = ctypes.WinDLL('psapi', use_last_error=True)
    psapi.EnumDeviceDrivers.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    psapi.GetDeviceDriverFileNameW.argtypes = [ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    bases = (ctypes.c_void_p * 4096)()
    needed = wintypes.DWORD()
    if not psapi.EnumDeviceDrivers(bases, ctypes.sizeof(bases), ctypes.byref(needed)) or needed.value > ctypes.sizeof(bases):
        raise RuntimeError('process-use inventory incomplete: loaded drivers unreadable')
    root = os.environ.get('SystemRoot', 'C:\\Windows')
    name = ctypes.create_unicode_buffer(32768)
    paths = []
    for base in bases[:needed.value // ctypes.sizeof(ctypes.c_void_p)]:
        if not base or not psapi.GetDeviceDriverFileNameW(base, name, len(name)):
            raise RuntimeError('process-use inventory incomplete: loaded driver name unreadable')
        value = name.value
        paths.append(value[4:] if value.startswith('\\??\\') else
                     root + value[11:] if value.lower().startswith('\\systemroot\\') else value)
    return paths


def enable_debug_privilege():
    import ctypes
    from ctypes import wintypes

    class Privilege(ctypes.Structure):
        _fields_ = [('count', wintypes.DWORD), ('low', wintypes.DWORD),
                    ('high', wintypes.LONG), ('attributes', wintypes.DWORD)]

    security = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    security.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPVOID]
    security.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(Privilege),
                                               wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    token_adjust_privileges = 0x20
    privilege_enabled = 2
    if not security.OpenProcessToken(-1, token_adjust_privileges, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        privilege = Privilege(count=1, attributes=privilege_enabled)
        luid = ctypes.byref(privilege, Privilege.low.offset)
        if not security.LookupPrivilegeValueW(None, 'SeDebugPrivilege', luid):
            raise ctypes.WinError(ctypes.get_last_error())
        if not security.AdjustTokenPrivileges(token, False, ctypes.byref(privilege), 0, None, None) or ctypes.get_last_error():
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(token)


def extended(path):
    path = str(path)
    return '\\\\?\\' + os.path.abspath(path) if os.name == 'nt' and not path.startswith('\\\\?\\') else path


def delete(path):
    import shutil
    def writable(function, name, error):
        if os.name != 'nt' or not isinstance(error, PermissionError):
            raise error
        os.chmod(name, stat.S_IWRITE)
        function(name)
    target = extended(path)
    if os.path.isdir(target) and not os.path.islink(target) and sys.version_info < (3, 12):
        shutil.rmtree(target, onerror=lambda function, name, info: writable(function, name, info[1]))
    elif os.path.isdir(target) and not os.path.islink(target):
        shutil.rmtree(target, onexc=writable)
    else:
        try:
            os.unlink(target)
        except PermissionError as error:
            writable(os.unlink, target, error)


def protected_process(pid):
    import ctypes

    class ExtendedBasicInformation(ctypes.Structure):
        _fields_ = [('Size', ctypes.c_size_t), ('ExitStatus', ctypes.c_int32), ('PebBaseAddress', ctypes.c_void_p),
                    ('AffinityMask', ctypes.c_size_t), ('BasePriority', ctypes.c_int32),
                    ('UniqueProcessId', ctypes.c_size_t), ('InheritedFromUniqueProcessId', ctypes.c_size_t),
                    ('Flags', ctypes.c_uint32)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    ntdll = ctypes.WinDLL('ntdll')
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    ntdll.NtQueryInformationProcess.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong,
                                                ctypes.POINTER(ctypes.c_ulong)]
    handle = kernel.OpenProcess(0x1000, 0, pid)
    if not handle:
        return False
    try:
        returned = ctypes.c_ulong()
        level = ctypes.c_ubyte()
        status = ntdll.NtQueryInformationProcess(handle, 61, ctypes.byref(level), 1, ctypes.byref(returned))
        if status == 0 and level.value != 0:
            return True
        extended = ExtendedBasicInformation()
        extended.Size = ctypes.sizeof(extended)
        status = ntdll.NtQueryInformationProcess(handle, 0, ctypes.byref(extended), ctypes.sizeof(extended),
                                                 ctypes.byref(returned))
        return status == 0 and bool(extended.Flags & 0x81)
    finally:
        kernel.CloseHandle(handle)


PROC_SCAN = r"""
import json, os, re, sys
from pathlib import Path
by_namespace = sys.argv[2:] == ['--by-namespace']


def exited(proc):
    try:
        status = (proc / 'status').read_text()
    except (FileNotFoundError, ProcessLookupError):
        return True
    return bool(re.search(r'^State:\s+Z', status, re.M) and re.search(r'^Threads:\s+1$', status, re.M))


def kernel_thread(proc):
    try:
        return bool(int((proc / 'stat').read_text().rsplit(')', 1)[1].split()[6]) & 0x00200000)
    except (FileNotFoundError, ProcessLookupError):
        return False

paths, namespaces = [], {}
for proc in Path(sys.argv[1]).iterdir():
    if not proc.name.isdigit() or int(proc.name) == os.getpid():
        continue
    found = []
    try:
        command = (proc / 'cmdline').read_bytes()
        for name in ('cwd', 'exe'):
            try:
                found.append(os.readlink(proc / name))
            except FileNotFoundError:
                pass
        for fd in (proc / 'fd').iterdir():
            try:
                found.append(os.readlink(fd))
            except FileNotFoundError:
                pass
        text = command.decode('utf-8', 'replace') + (proc / 'environ').read_bytes().decode('utf-8', 'replace')
        for item in text.split('\x00'):
            found.extend(re.findall(r"/[^\x00:=\x27\x22;,|()<>]+", item))
            found.extend(re.findall(r"/[^\s\x00:=\x27\x22;,|()<>]+", item))
        for line in (proc / 'maps').read_bytes().decode('utf-8', 'surrogateescape').splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[5].startswith('/'):
                found.append(fields[5].removesuffix(' (deleted)'))
        if by_namespace:
            if os.readlink(proc / 'root') != '/':
                sys.exit('process ' + proc.name + ' has a changed root')
            namespace = os.readlink(proc / 'ns' / 'mnt')
            if namespace not in namespaces:
                namespaces[namespace] = dict(mountinfo=(proc / 'mountinfo').read_text(), paths=[])
            namespaces[namespace]['paths'].extend(found)
    except (FileNotFoundError, ProcessLookupError):
        if by_namespace:
            if exited(proc) or kernel_thread(proc):
                continue
            sys.exit('process ' + proc.name + ' is running but its files are unreadable')
    except PermissionError:
        sys.exit('/proc not readable')
    paths.extend(found)
print(json.dumps(list(namespaces.values()) if by_namespace else paths))
"""


def drvfs_mounts(mountinfo):
    def unescape(field):
        return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), field)
    mounts = {}
    for line in mountinfo.splitlines():
        fields = line.split()
        match = re.search(r'(?:^|,)aname=drvfs;path=([^;,]+)', fields[-1]) if ' - ' in line else None
        if match:
            root = unescape(fields[3]).strip('/')
            target = unescape(match[1]).rstrip('\\') + ('\\' + root.replace('/', '\\') if root else '')
            mounts[unescape(fields[4]).rstrip('/') or '/'] = target
    return sorted(mounts.items(), key=lambda mount: -len(mount[0]))


def windows_from_wsl(path, mounts):
    for point, target in mounts:
        if path == point or path.startswith(point.rstrip('/') + '/'):
            return target + '\\' + path[len(point):].strip('/').replace('/', '\\')
    return None


def wsl(distro, *command, stdin=None):
    result = subprocess.run(['wsl.exe', '-d', distro, '-u', 'root', '-e', *command], input=stdin,
                            capture_output=True, encoding='utf-8', errors='surrogateescape')
    if result.returncode:
        raise RuntimeError('process-use inventory incomplete: WSL distro ' + distro + ': ' + result.stderr.strip())
    return result.stdout


def running_distros():
    listing = subprocess.run(['wsl.exe', '--list', '--running', '--quiet'], capture_output=True, check=True).stdout
    text = listing.decode('utf-16-le') if b'\x00' in listing else listing.decode()
    distros = [line.strip() for line in text.splitlines() if line.strip()]
    if not distros:
        raise RuntimeError('process-use inventory incomplete: vmmemWSL is running but no WSL distro is listed')
    return distros


def wsl_references():
    paths = []
    for distro in running_distros():
        for namespace in json.loads(wsl(distro, 'python3', '-', '/proc', '--by-namespace', stdin=PROC_SCAN)):
            mounts = drvfs_mounts(namespace['mountinfo'])
            paths.extend(filter(None, (windows_from_wsl(path, mounts) for path in namespace['paths'])))
    return paths


SCAN_PATH = '/usr/local/libexec/coldcleaner-proc-scan.py'
NEEDS_SUDO = 'IN USE: process inventory needs passwordless sudo (see README#sudo)'
SUDO_REFUSED = re.compile(r"^sudo: (a password is required|sorry, user .* is not allowed"
                          r"|interactive authentication is required|I'm sorry .*\. I'm afraid I can't do that)", re.M)


def sudo_run(command, **kwargs):
    sudo = [] if os.geteuid() == 0 else ['sudo', '-n']
    try:
        result = subprocess.run(sudo + command, capture_output=True, **kwargs)
    except FileNotFoundError:
        if sudo:
            raise ValueError(NEEDS_SUDO) from None
        raise
    stderr = result.stderr if isinstance(result.stderr, str) else os.fsdecode(result.stderr)
    if sudo and result.returncode and SUDO_REFUSED.search(stderr):
        raise ValueError(NEEDS_SUDO)
    return result


def installed_scan():
    try:
        return Path(SCAN_PATH).read_text() == PROC_SCAN
    except (OSError, ValueError):
        return False


def darwin_references():
    def capture(command):
        result = sudo_run(command)
        if result.returncode:
            raise RuntimeError('process-use inventory incomplete: ' + command[0] + ': '
                               + result.stderr.decode(errors='replace').strip())
        return result

    lsof = capture(['lsof', '-nP', '-Fn'])
    paths = []
    for line in os.fsdecode(lsof.stderr).splitlines():
        warning = re.fullmatch(r"lsof: WARNING: can't stat\(\) \S+ file system (/.+)", line)
        if warning:
            paths.append(warning[1])
        elif not (paths and (line.strip() == 'Output information may be incomplete.'
                             or re.fullmatch(r'\s+assuming "dev=[0-9]+" from mount table', line))):
            raise RuntimeError('process-use inventory incomplete: lsof: ' + line)
    for line in lsof.stdout.splitlines():
        if line.startswith(b'n/'):
            name = os.fsdecode(line[1:])
            decoded = os.fsdecode(re.sub(rb"\\x([0-9a-fA-F]{2})", lambda match: bytes([int(match[1], 16)]), line[1:]))
            paths.extend({name, decoded})
    for line in os.fsdecode(capture(['ps', '-axww', '-o', 'command=']).stdout).splitlines():
        paths.extend(re.findall(r"/[^\x00:=\x27\x22;,|()<>]+", line))
        paths.extend(re.findall(r"/[^\s\x00:=\x27\x22;,|()<>]+", line))
    return paths


def references(proc='/proc'):
    if sys.platform == 'darwin':
        return darwin_references()
    if os.name == 'nt':
        script = "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
        result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                                capture_output=True, text=True, check=True)
        rows = json.loads(result.stdout)
        rows = rows if isinstance(rows, list) else [rows]
        paths, machines = [], []
        for row in rows:
            if row['ProcessId'] in (0, 4, os.getpid()):
                continue
            if not row.get('CommandLine'):
                if not row.get('ExecutablePath') and protected_process(row['ProcessId']):
                    continue
                if not row.get('ExecutablePath') and row.get('Name') in ('vmmemWSL', 'vmmemCmZygote'):
                    machines.append(row['Name'])
                    continue
                if exited(row['ProcessId']):
                    continue
                raise RuntimeError('process-use inventory incomplete: CommandLine unreadable for process ' +
                                   str(row['ProcessId']) + '; Windows reclaim requires elevation')
            if row.get('ExecutablePath'):
                paths.append(row['ExecutablePath'])
            paths.extend(windows_paths(windows_arguments(row['CommandLine'])))
        if 'vmmemCmZygote' in machines and any((row.get('Name') or '').lower().startswith('windowssandbox') for row in rows):
            raise RuntimeError('process-use inventory incomplete: a Windows Sandbox session is running')
        if machines.count('vmmemWSL') > 1:
            raise RuntimeError('process-use inventory incomplete: more than one WSL VM is running')
        if 'vmmemWSL' in machines:
            paths.extend(wsl_references())
        return paths + drivers()
    if os.geteuid() == 0:
        scan = ['-c', PROC_SCAN]
    elif installed_scan():
        scan = ['-I', SCAN_PATH]
    else:
        raise ValueError(NEEDS_SUDO)
    result = sudo_run(['python3', *scan, str(proc)], text=True)
    if result.returncode and result.stderr.strip() == '/proc not readable':
        raise ValueError('process inventory incomplete: /proc not readable')
    if result.returncode:
        raise RuntimeError('process-use inventory incomplete: ' + result.stderr.strip())
    return json.loads(result.stdout)


def windows_security(path, descriptor=None):
    import ctypes
    from ctypes import wintypes
    api = ctypes.WinDLL('advapi32', use_last_error=True)
    api.GetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID,
                                     wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    api.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID]
    if descriptor is not None:
        buffer = ctypes.create_string_buffer(bytes.fromhex(descriptor))
        control = ctypes.c_ushort(); revision = wintypes.DWORD()
        if not api.GetSecurityDescriptorControl(buffer, ctypes.byref(control), ctypes.byref(revision)):
            raise ctypes.WinError(ctypes.get_last_error())
        flags = 7 | (0x80000000 if control.value & 0x1000 else 0x20000000)
        if not api.SetFileSecurityW(str(path), flags, buffer):
            raise ctypes.WinError(ctypes.get_last_error())
    needed = wintypes.DWORD()
    api.GetFileSecurityW(str(path), 7, None, 0, ctypes.byref(needed))
    if not needed.value:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_string_buffer(needed.value)
    if not api.GetFileSecurityW(str(path), 7, buffer, len(buffer), ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.raw[:needed.value].hex()


def mount_boundary(path):
    path = Path(os.path.abspath(path))
    if os.name != 'nt' and Path('/proc/self/mountinfo').exists():
        for row in Path('/proc/self/mountinfo').read_text().splitlines():
            name = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), row.split()[4])
            if Path(name).is_relative_to(path):
                raise ValueError('mounted filesystem in cleanup candidate: ' + name)
    elif os.path.ismount(path):
        raise ValueError('cleanup candidate is a mount point')


def package_cache(path):
    return bool(set(str(path).replace('\\', '/').casefold().split('/')) &
                {'.cache', '.npm', '.cargo', '.bun', 'node-compile-cache', 'npm-cache', 'pip-cache', 'uv-cache', 'go-build'})


def reject_package_caches(root):
    pending = [root]
    while pending:
        item = pending.pop()
        if package_cache(item):
            raise ValueError('package caches are excluded: ' + str(item))
        try:
            with os.scandir(item) as entries:
                pending.extend(Path(entry.path) for entry in entries if entry.is_dir(follow_symlinks=False)
                               and not getattr(entry.stat(follow_symlinks=False), 'st_file_attributes', 0) & 1024)
        except OSError:
            continue


OS_STAMP_XATTRS = frozenset(('com.apple.provenance', 'com.apple.quarantine'))


def xattr_names(path):
    if hasattr(os, 'listxattr'):
        return os.listxattr(path, follow_symlinks=False)
    if sys.platform != 'darwin':
        raise ValueError('extended attributes cannot be read on this platform: ' + str(path))
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    libc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]
    libc.listxattr.restype = ctypes.c_ssize_t
    def listed(names, size):
        size = libc.listxattr(os.fsencode(path), names, size, 1)
        if size < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(path))
        return size
    size = listed(None, 0)
    if size == 0:
        return []
    names = ctypes.create_string_buffer(size)
    size = listed(names, size)
    return [os.fsdecode(name) for name in names.raw[:size].split(b'\0') if name]


def has_xattrs_beyond_os_stamps(path):
    return not OS_STAMP_XATTRS.issuperset(xattr_names(path))


def allocation(info):
    return getattr(info, 'st_blocks', (info.st_size + 511) // 512) * 512


def measure(path, deadline, skip=frozenset()):
    try:
        root = os.lstat(extended(path))
    except FileNotFoundError:
        return dict(bytes=0, complete=True)
    except OSError:
        return dict(bytes=0, complete=False)
    total = allocation(root); complete = True
    pending = [extended(path)] if stat.S_ISDIR(root.st_mode) and not getattr(root, 'st_file_attributes', 0) & 1024 else []
    while pending:
        try:
            with os.scandir(pending.pop()) as entries:
                for entry in entries:
                    if time.monotonic() > deadline:
                        return dict(bytes=total, complete=False)
                    if skip and os.path.normcase(entry.path) in skip:
                        continue
                    try:
                        info = os.lstat(entry.path) if entry.is_dir(follow_symlinks=False) else entry.stat(follow_symlinks=False)
                    except OSError:
                        complete = False
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if info.st_dev != root.st_dev or getattr(info, 'st_file_attributes', 0) & 1024:
                            continue
                        pending.append(entry.path)
                    total += allocation(info)
        except OSError:
            complete = False
    return dict(bytes=total, complete=complete)


def du_available():
    import shutil
    return os.name != 'nt' and shutil.which('du') is not None


def du_total(paths, deadline):
    if time.monotonic() >= deadline:
        return None
    try:
        result = subprocess.run(['du', '-skx', '--', *paths], capture_output=True,
                                timeout=max(0.0, deadline - time.monotonic()))
        lines = result.stdout.decode(errors='replace').splitlines()
        total = sum(int(line.split('\t', 1)[0]) for line in lines) * 1024
    except (subprocess.TimeoutExpired, ValueError):
        return None
    return total, result.returncode == 0 and len(lines) == len(paths)


def same_device(path, device):
    try:
        return os.lstat(path).st_dev == device
    except OSError:
        return False


def du_size(path, excluded, deadline):
    inside = [item for item in excluded if item.startswith(path.rstrip(os.sep) + os.sep)]
    device = os.lstat(path).st_dev if inside else None
    outer = sorted(item for item in inside if same_device(item, device)
                   and not any(item.startswith(other.rstrip(os.sep) + os.sep) for other in inside))
    gross = du_total([path], deadline)
    held = du_total(outer, deadline) if gross and outer else (0, True)
    if gross is None or held is None:
        return None
    return dict(bytes=max(0, gross[0] - held[0]), complete=gross[1] and held[1])


def du_sizes(candidates, deadline, excluded):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(os.cpu_count() or 1) as pool:
        found = list(pool.map(lambda item: du_size(item[0], excluded, deadline), candidates))
    return {item: size for item, size in zip(candidates, found) if size}


def python_sizes(candidates, deadline, excluded):
    sizes = {}
    for _ in range(3):
        pending = [item for item in candidates if item not in sizes or not sizes[item]['complete']]
        for index, item in enumerate(pending):
            now = time.monotonic()
            if now > deadline:
                break
            size = measure(item[0], now + (deadline - now) / (len(pending) - index), excluded)
            if item not in sizes or size['bytes'] >= sizes[item]['bytes']:
                sizes[item] = size
    return sizes


def size_cache(path):
    try:
        found = json.loads(Path(expanded(path)).read_text())
    except FileNotFoundError:
        return {}, []
    except (OSError, ValueError) as error:
        return {}, [f'Size cache unreadable, measured from scratch: {error}']
    valid = lambda entry: (isinstance(entry, dict) and type(entry.get('bytes')) is int and type(entry.get('mtime')) is int
                           and isinstance(entry.get('at'), str))
    if not isinstance(found, dict) or not all(isinstance(key, str) and valid(entry) for key, entry in found.items()):
        return {}, ['Size cache malformed, measured from scratch']
    return found, []


def save_size_cache(path, sizes):
    target = Path(expanded(path))
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f'{target.name}.{os.getpid()}.tmp')
        temporary.write_text(json.dumps(sizes, sort_keys=True))
        os.replace(temporary, target)
    except OSError as error:
        return [f'Size cache not saved: {error}']
    return []


def unlisted(roots, covered, skip, seconds, state=None, save=False):
    import glob
    deadline = time.monotonic() + seconds
    previous, notes = size_cache(state) if state else ({}, [])
    key = lambda path: os.path.normcase(extended(os.path.abspath(path)))
    excluded = {key(path) for path in skip}
    cut_short = lambda: dict(rows=[dict(path=path, bytes=old['bytes'], complete=True, measured=old['at'])
                                   for path, old in previous.items() if key(path) not in excluded],
                             complete=False, notes=notes, grew=[])
    for pattern in covered:
        for path in glob.iglob(expanded(pattern)):
            if time.monotonic() > deadline:
                return cut_short()
            excluded.add(key(path))
    scanned = []
    for pattern in roots:
        for root in glob.iglob(expanded(pattern)):
            if time.monotonic() > deadline:
                return cut_short()
            root = os.path.abspath(root)
            covered_root = any(key(parent) in excluded for parent in [root, *map(str, Path(root).parents)])
            if os.path.isdir(root) and not os.path.islink(root) and root not in scanned and not covered_root:
                scanned.append(root)
    excluded.update(key(path) for path in scanned)
    candidates, complete, mtimes, unseen = [], True, {}, set()
    for root in scanned:
        try:
            device = os.lstat(extended(root)).st_dev
            entries = os.scandir(extended(root))
        except OSError:
            complete = False
            unseen.update(path for path in previous if os.path.dirname(path) == root)
            continue
        with entries:
            children = []
            for entry in entries:
                if time.monotonic() > deadline:
                    return cut_short()
                children.append(entry)
        for entry in sorted(children, key=lambda entry: entry.name):
            if time.monotonic() > deadline:
                return cut_short()
            try:
                info = os.lstat(entry.path)
            except OSError:
                complete = False
                unseen.add(os.path.join(root, entry.name))
                continue
            if (os.path.normcase(entry.path) not in excluded and stat.S_ISDIR(info.st_mode) and info.st_dev == device
                    and not getattr(info, 'st_file_attributes', 0) & 1024):
                candidates.append((entry.path, os.path.join(root, entry.name)))
                mtimes[os.path.join(root, entry.name)] = info.st_mtime_ns
    candidates.sort(key=lambda item: previous.get(item[1], {}).get('mtime') == mtimes[item[1]])
    sizing = du_sizes if du_available() else python_sizes
    now = time.monotonic()
    sizes = sizing(candidates, now + max(0, deadline - now) * 0.75, excluded)
    at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    kept = {path: previous[path] for path in unseen if path in previous}
    rows, grew = [dict(path=path, bytes=old['bytes'], complete=True, measured=old['at']) for path, old in kept.items()], []
    for item in candidates:
        shown = item[1]; size = sizes.get(item); old = previous.get(shown)
        if size and size['complete']:
            kept[shown] = dict(bytes=size['bytes'], mtime=mtimes[shown], at=at)
            rows.append(dict(path=shown, **size))
            if old and size['bytes'] > old['bytes']:
                grew.append(dict(path=shown, bytes=size['bytes'], before=old['bytes'], since=old['at']))
            continue
        if old:
            kept[shown] = old
            rows.append(dict(path=shown, bytes=old['bytes'], complete=True, measured=old['at']))
        elif size:
            rows.append(dict(path=shown, **size))
    complete = complete and len(rows) == len(candidates) + len(unseen & kept.keys()) and all(row['complete'] for row in rows)
    for item in candidates:
        if sizes.get(item, {}).get('complete') or time.monotonic() >= deadline:
            continue
        children = []
        try:
            device = os.lstat(item[0]).st_dev
            with os.scandir(item[0]) as entries:
                for entry in entries:
                    if time.monotonic() >= deadline:
                        break
                    try:
                        info = os.lstat(entry.path)
                    except OSError:
                        continue
                    if (key(entry.path) not in excluded and stat.S_ISDIR(info.st_mode) and info.st_dev == device
                            and not getattr(info, 'st_file_attributes', 0) & 1024):
                        children.append((entry.path, os.path.join(item[1], entry.name)))
        except OSError:
            continue
        child_sizes = sizing(children, deadline, excluded)
        if child_sizes:
            child = max(child_sizes, key=lambda child: child_sizes[child]['bytes'])
            rows.append(dict(path=child[1], **child_sizes[child]))
    if state and save:
        notes += save_size_cache(state, kept)
    return dict(rows=sorted(rows, key=lambda row: -row['bytes']), complete=complete, notes=notes,
                grew=sorted(grew, key=lambda row: row['before'] - row['bytes']))


def tree(path, hashes=False, approval=False):
    present(path)
    path = Path(path)
    mount_boundary(path)
    path = Path(extended(path))
    approval = approval and os.name == 'nt'
    if approval:
        require_ntfs(path)
    reject_package_caches(path)
    result = {}; security = {}; allocated = logical = files = 0; newest = path.lstat().st_mtime
    entries = []
    device = path.lstat().st_dev
    pending = [path]
    while pending:
        item = pending.pop()
        if package_cache(item):
            raise ValueError('package caches are excluded: ' + str(item))
        info = item.lstat()
        if info.st_dev != device:
            raise ValueError('filesystem boundary: ' + str(item))
        if os.name != 'nt' and (has_xattrs_beyond_os_stamps(item) or
                info.st_uid != os.geteuid() or info.st_gid != os.getegid() or info.st_mode & 0o7000):
            raise ValueError('access metadata requires separate preservation: ' + str(item))
        if item.suffix.casefold() in ('.vhd', '.vhdx', '.qcow2', '.vmdk', '.vdi'):
            raise ValueError('VM disk requires hypervisor dependency proof: ' + str(item))
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 1024:
            raise ValueError('symlink or reparse point: ' + str(item))
        change = windows_file_safety(item, approval) if os.name == 'nt' else None
        if item.name == '.keep-local':
            raise ValueError('.keep-local: ' + str(item))
        if item.name.casefold() == LEASE:
            check_lease(item)
        if item.name.casefold().endswith(MARKER):
            check_marker(item)
        if item.name.casefold() == '.obsidian':
            raise ValueError('protected location: Obsidian vault ' + str(item.parent))
        newest = max(newest, info.st_mtime)
        allocated += allocation(info)
        relative = str(item.relative_to(path.parent)).replace(os.sep, '/')
        entry = (relative, stat.S_IFMT(info.st_mode), info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        entries.append((*entry, change, info.st_ino) if approval else entry)
        if hashes:
            security[relative] = (windows_security(item) if os.name == 'nt' else
                                  dict(mode=info.st_mode & 0o777, uid=info.st_uid,
                                       gid=info.st_gid, mtime_ns=info.st_mtime_ns))
        if '\\' in relative or any(ord(char) < 32 for char in relative):
            raise ValueError('unsupported archive member name: ' + repr(relative))
        if item.is_dir():
            pending.extend(item.iterdir())
            if hashes:
                result[relative] = None
        elif item.is_file():
            logical += info.st_size; files += 1
            if hashes:
                with item.open('rb') as stream:
                    result[relative] = sha256_hex(stream)
        else:
            raise ValueError('special file: ' + str(item))
    digest = hashlib.sha256(json.dumps(sorted(entries)).encode()).hexdigest()
    return dict(bytes=allocated, logical_bytes=logical, files=files, newest=newest, manifest=result, security=security, digest=digest)


PERSONAL_FOLDERS = ('Documents', 'Desktop', 'Pictures', 'Library', 'iCloud Drive', 'iCloudDrive', 'Google Drive')


def protected_location(path, extra=()):
    home = Path.home()
    locations = [str(home / name) for name in PERSONAL_FOLDERS]
    locations += [os.path.expandvars(os.path.expanduser(item)) for item in extra]
    if os.name == 'nt':
        system = os.environ.get('SystemRoot', 'C:\\Windows')
        if not contained(path, os.path.join(system, 'Temp')):
            locations.append(system)
        locations += [os.environ[name] for name in ('ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432',
                                                     'OneDrive', 'OneDriveConsumer', 'OneDriveCommercial') if os.environ.get(name)]
        anchor = Path(os.path.abspath(path)).parts[1:2]
        if anchor and anchor[0].casefold().startswith('program files'):
            return anchor[0]
    else:
        locations += ['/etc', '/usr', '/System', '/mnt/shared-memory']
    for location in locations:
        if overlap(path, location):
            return location
    if contained(path, str(home)):
        first = Path(os.path.abspath(path)).relative_to(os.path.abspath(home)).parts[:1]
        if first and first[0].casefold().startswith('onedrive'):
            return str(home / first[0])
    return None


LOCAL_POLICY = '~/.config/coldcleaner/local.json'


def expanded(item):
    return os.path.expandvars(os.path.expanduser(item))


def local_policy():
    path = expanded(LOCAL_POLICY)
    try:
        policy = json.loads(Path(path).read_text())
    except FileNotFoundError:
        raise ValueError('no host-local policy at ' + path) from None
    except (OSError, ValueError) as error:
        raise ValueError('host-local policy unreadable: ' + path + ': ' + str(error)) from None
    if not isinstance(policy, dict) or not set(policy) <= {'roots', 'archive'} or not all(
            isinstance(items, list) and all(isinstance(item, str) and os.path.isabs(expanded(item)) for item in items)
            for items in policy.values()):
        raise ValueError('host-local policy invalid: ' + path + ' needs absolute "roots" and "archive" lists')
    return policy


def locally_allowed(path, worktree):
    import glob
    policy = local_policy()
    if worktree:
        allowed = any(contained(path, root) for root in policy.get('roots', []))
    else:
        target = os.path.normcase(os.path.normpath(path))
        allowed = any(target == os.path.normcase(os.path.normpath(found))
                      for pattern in policy.get('archive', []) for found in glob.glob(expanded(pattern)))
    if not allowed:
        raise ValueError('outside host-local policy ' + expanded(LOCAL_POLICY) + ': ' + str(path))


LEASE = '.coldcleaner-lease'
APPROVAL_STALE = 'APPROVAL STALE: changed since it was planned; approve it again from a new dry-run plan'


def check_lease(lease):
    if not os.path.lexists(lease):
        return
    try:
        text = Path(lease).read_text(encoding='utf-8').strip()
        if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', text, re.ASCII):
            raise ValueError(text)
        expiry = datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
    except (OSError, ValueError):
        raise ValueError('unreadable .coldcleaner-lease, protecting: ' + str(lease)) from None
    if expiry > time.time():
        raise ValueError('leased until ' + text + ': ' + str(lease))



def check_leases(folder, file_marker=''):
    try:
        names = os.listdir(folder)
    except OSError as error:
        raise ValueError('lease check incomplete, protecting: ' + str(error)) from None
    for name in names:
        if name.casefold() == LEASE:
            check_lease(Path(folder) / name)
        if name.casefold() in (MARKER, file_marker.casefold()):
            check_marker(Path(folder) / name)


MARKER = '.cold-artifact.json'
UTC_TIME = re.compile(r'[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z')


def marker_time(value):
    if not isinstance(value, str) or not UTC_TIME.fullmatch(value):
        raise ValueError(value)
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def nonempty(value):
    if not isinstance(value, str) or not value:
        raise ValueError(value)
    return value


def fields(value, required, allowed):
    if not isinstance(value, dict) or not set(required) <= set(value) <= set(allowed):
        raise ValueError(value)
    return value


def marker_retention(marker):
    marker = fields(marker, ('schema_version', 'retention', 'provenance'), ('schema_version', 'retention', 'provenance'))
    if type(marker['schema_version']) is not int or marker['schema_version'] != 1:
        raise ValueError(marker['schema_version'])
    retention = fields(marker['retention'], ('owner', 'policy'), ('owner', 'policy', 'expires', 'preserved_at'))
    provenance = fields(marker['provenance'], ('producer', 'created_at'), ('producer', 'created_at', 'run_id', 'repo'))
    for value in [retention['owner'], provenance['producer']] + [
            item[key] for item, key in ((retention, 'preserved_at'), (provenance, 'run_id')) if key in item]:
        nonempty(value)
    created = marker_time(provenance['created_at'])
    if 'repo' in provenance:
        repo = fields(provenance['repo'], ('name', 'commit'), ('name', 'commit', 'snapshot_tree'))
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', nonempty(repo['name'])) or \
                not re.fullmatch(r'[0-9a-f]{40}', nonempty(repo['commit'])) or \
                repo.get('snapshot_tree') is not None and not re.fullmatch(r'[0-9a-f]{64}', nonempty(repo['snapshot_tree'])):
            raise ValueError(repo)
    if retention['policy'] not in ('temporary', 'keep') or (retention['policy'] == 'temporary') != ('expires' in retention):
        raise ValueError(retention)
    if 'expires' in retention and marker_time(retention['expires']) <= created:
        raise ValueError(retention['expires'])
    return retention


def check_marker(path):
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise ValueError(path)
        retention = marker_retention(json.loads(Path(path).read_text(encoding='utf-8')))
    except (OSError, ValueError, TypeError, KeyError):
        raise ValueError('invalid artifact marker, protecting: ' + str(path)) from None
    if retention['policy'] == 'keep':
        raise ValueError('artifact marker says keep (owner ' + retention['owner'] + '): ' + str(path))
    if marker_time(retention['expires']) > datetime.now(timezone.utc):
        raise ValueError('artifact marker owned by ' + retention['owner'] + ' until ' + retention['expires'] + ': ' + str(path))
    if retention['owner'].casefold() in running_programs():
        raise ValueError('artifact marker owner ' + retention['owner'] + ' is running: ' + str(path))


def running_programs():
    try:
        if os.name == 'nt':
            script = "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
            rows = json.loads(subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
                                             capture_output=True, text=True, check=True).stdout)
            rows = rows if isinstance(rows, list) else [rows]
            commands = [(row['ProcessId'], [row.get('Name') or ''] + windows_arguments(row['CommandLine']))
                        for row in rows if row['ProcessId'] not in (0, 4)
                        and (row.get('CommandLine') or unreadable_command_line(row))]
            commands += [(None, args) for distro in running_distros()
                         for _, args in ps_rows(wsl(distro, 'ps', '-A', '-ww', '-o', 'pid=,args='))]
        else:
            command = ['ps', '-A', '-ww', '-o', 'pid=,args=']
            if sys.platform == 'darwin':
                result = sudo_run(command, text=True)
                if result.returncode:
                    raise ValueError(result.stderr.strip())
                listing = result.stdout
            else:
                if os.geteuid() and hides_processes(Path('/proc/self/mountinfo').read_text()):
                    raise ValueError("/proc hides other users' processes")
                listing = subprocess.run(command, capture_output=True, text=True, check=True).stdout
            commands = ps_rows(listing)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.CalledProcessError) as error:
        raise ValueError('artifact marker owner check incomplete, protecting: ' + str(error)) from None
    return {re.split(r'[\\/]', token)[-1].split('.')[0].casefold()
            for pid, tokens in commands if pid != os.getpid() for token in tokens}


def ps_rows(listing):
    rows = [(int(pid), args.split()) for pid, _, args in
            (line.strip().partition(' ') for line in listing.split('\n') if line.strip())]
    if not rows or not all(args for _, args in rows):
        raise ValueError('empty process list or a process without a command line')
    return rows


def hides_processes(mountinfo):
    for row in mountinfo.split('\n'):
        fields = row.split(' - ')
        if len(fields) == 2 and row.split()[4] == '/proc' and fields[1].split()[0] == 'proc':
            options = {key: value for key, _, value in (option.partition('=') for option in fields[1].split()[-1].split(','))}
            return options.get('hidepid', '0') not in ('0', 'off')
    return False


def unreadable_command_line(row):
    if not row.get('ExecutablePath') and (row.get('Name') in ('vmmemWSL', 'vmmemCmZygote')
                                          or protected_process(row['ProcessId'])):
        return False
    if exited(row['ProcessId']):
        return False
    raise ValueError('CommandLine unreadable for process ' + str(row['ProcessId']))


def excluded(path, patterns):
    import glob
    return any(overlap(path, found) for pattern in patterns for found in glob.glob(expanded(pattern)))


def present(path):
    if not os.path.lexists(path):
        raise ValueError('no longer exists; removed by another program')


def check_holds_above(path):
    for parent in path.parents:
        check_leases(parent, path.name + MARKER if parent == path.parent else '')


class ActivityPaths:
    def __init__(self):
        self.threads = {}
        self.references = {}

    def thread_key(self, path):
        if path not in self.threads:
            self.threads[path] = real_key(path)
        return self.threads[path]

    def reference_key(self, path):
        if path not in self.references:
            self.references[path] = os.path.normcase(os.path.realpath(path))
        return self.references[path]


def guard(path, days=0, activity=None, protected=(), approval=False, activity_paths=None, broad=()):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or path in (Path(path.anchor), Path.home()):
        raise ValueError('invalid cleanup root')
    location = protected_location(path, protected)
    if location:
        raise ValueError('protected location: ' + location)
    present(path)
    for parent in (path, *path.parents):
        if parent.is_symlink() or getattr(parent.lstat(), 'st_file_attributes', 0) & 1024 or (parent / '.keep-local').exists():
            raise ValueError('.keep-local or symlink ancestor: ' + str(parent))
        if (parent / '.obsidian').exists():
            raise ValueError('protected location: Obsidian vault ' + str(parent))
        if parent.is_dir():
            check_leases(parent, path.name + MARKER if parent == path.parent else '')
    if activity is None:
        activity = workspaces(time.time() - days * 86400)
        if activity['blocked']:
            raise ValueError('; '.join(activity['blocked']))
        activity['references'] = references()
    activity_paths = activity_paths or ActivityPaths()
    path_key = real_key(path)
    normalized = path_key if sys.platform != 'darwin' else os.path.realpath(path)
    prefix = normalized.rstrip(os.sep) + os.sep
    broad = [expanded(item) for item in (*broad, str(Path.home()))]
    for name, reference, updated in activity['threads']:
        thread_key = activity_paths.thread_key(reference)
        held = overlap_keys(path_key, thread_key)
        if held and path_key != thread_key and contains_key(thread_key, path_key) and broad_folder(reference, thread_key, broad):
            held = False
        if (updated is None or updated > time.time() - days * 86400) and held:
            raise ValueError(f'{name} thread uses {reference}')
    for reference in activity['references']:
        reference = activity_paths.reference_key(reference)
        if reference.startswith(prefix) or reference == normalized:
            raise ValueError('running process uses ' + reference)
    info = tree(path, approval=True) if approval and os.name == 'nt' else tree(path)
    if info['newest'] > time.time() - days * 86400:
        raise ValueError('recent activity within %s days' % days)
    return info


NOT_A_REPOSITORY = re.compile(r'fatal: (invalid gitfile format|not a git repository \(or any )')
BAD_CONFIG = re.compile(r'fatal: bad config line \d+ in file ')


def disposable_stub(path, message=''):
    marker = Path(path) / '.git'
    if marker.is_file():
        return message.startswith('fatal: invalid gitfile format')
    if not marker.is_dir() or marker.is_symlink():
        return False
    if any(entry.is_symlink() or not entry.is_dir() for entry in marker.iterdir()):
        return False
    return not any(files for name in ('refs', 'logs', 'worktrees') for _, _, files in os.walk(marker / name))


def object_format(commit):
    return 'sha256' if len(commit) == 64 else 'sha1'


def reflog_ref(commit):
    if not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', commit):
        raise ValueError('invalid reflog commit: ' + commit)
    return 'refs/coldcleaner/reflog/' + commit


def repo(path, listing='', stub_ok=False, abandoned=False):
    present(path)
    shown = git(path, 'rev-parse', '--show-toplevel', check=False)
    if shown.returncode:
        message = shown.stderr.strip()
        if stub_ok and NOT_A_REPOSITORY.match(message) and disposable_stub(path, message):
            return None
        raise RuntimeError(message or 'Git check failed')
    top = shown.stdout.strip()
    if os.path.normcase(os.path.realpath(top)) != os.path.normcase(os.path.realpath(path)):
        if stub_ok and disposable_stub(path):
            return None
        raise ValueError('not a repository root')
    try:
        return repo_state(path, listing, abandoned)
    except RuntimeError as exc:
        raise ValueError('UNIQUE: Git repository unreadable: ' + str(exc)) from None


def repo_state(path, listing, abandoned=False):
    local_refs =git(path, 'for-each-ref', '--format=%(refname)',
                     'refs/worktree/', 'refs/bisect/', 'refs/rewritten/')
    if local_refs:
        raise ValueError('per-worktree refs require preservation: ' + ', '.join(local_refs.splitlines()))
    head = git(path, 'rev-parse', '--verify', '-q', 'HEAD', check=False).stdout.strip()
    target = git(path, 'symbolic-ref', '-q', 'HEAD', check=False).stdout.strip()
    if not head and (not target.startswith('refs/heads/') or git(path, 'for-each-ref', '--format=%(refname)', target)):
        head = git(path, 'rev-parse', 'HEAD')
    branch = git(path, 'symbolic-ref', '-q', '--short', 'HEAD', check=False).stdout.strip()
    dirty = bool(git(path, 'status', '--porcelain=v1', '--untracked-files=all'))
    flags = git(path, 'ls-files', '-v').splitlines()
    dirty = dirty or any(line[:1].islower() or line.startswith('S ') for line in flags)
    unmerged = bool(git(path, 'ls-files', '--unmerged'))
    gitlinks = any(line.startswith('160000 ') for line in git(path, 'ls-files', '--stage').splitlines())
    dirty = dirty or unmerged or gitlinks
    index_only = (unmerged or gitlinks or any(line[:1].islower() or line.startswith('S ') for line in flags)
                  or git(path, 'diff', '--cached', '--quiet', check=False).returncode != 0
                  or in_progress(Path(git(path, 'rev-parse', '--path-format=absolute', '--git-dir'))))
    ignored = bool(git(path, 'ls-files', '--others', '--ignored', '--exclude-standard'))
    common = Path(git(path, 'rev-parse', '--path-format=absolute', '--git-common-dir'))
    if (common / 'info/grafts').exists() and (common / 'info/grafts').stat().st_size:
        raise ValueError('Git grafts prevent ancestry proof')
    refs = dict((line.split()[1], line.split()[0]) for line in listing.splitlines() if len(line.split()) == 2)
    published_refs = set(refs.values())
    published = head in published_refs
    if not published and head and published_refs:
        containing = set(git(path, 'for-each-ref', '--format=%(objectname)', '--contains', head).splitlines())
        published = bool(containing & published_refs)
    merged = False
    main = refs.get('refs/heads/main') or refs.get('refs/heads/master')
    if main and head and git(path, 'cat-file', '-e', main + '^{commit}', check=False).returncode == 0:
        merged = git(path, 'merge-base', '--is-ancestor', head, main, check=False).returncode == 0
        published = published or merged
    reflog = []
    if (published or abandoned) and (Path(path) / '.git').is_file():
        history = set()
        for ref in ['HEAD', *(['refs/heads/' + branch] if branch else [])]:
            history.update(git(path, 'reflog', 'show', '--format=%H', ref).splitlines())
        for commit in sorted(history - {head}):
            containing = set(git(path, 'for-each-ref', '--format=%(objectname)', '--contains', commit).splitlines())
            if not containing & published_refs:
                reflog.append(commit)
    linked = [line[9:] for line in git(path, 'worktree', 'list', '--porcelain').splitlines()
              if line.startswith('worktree ') and os.path.isdir(line[9:])
              and os.path.realpath(line[9:]) != os.path.realpath(path)]
    worktree = (Path(path) / '.git').is_file()
    linked_worktree = worktree and Path(git(path, 'rev-parse', '--path-format=absolute', '--git-dir')).resolve() != common.resolve()
    shared_stash = bool(git(path, 'stash', 'list'))
    stashes = not linked_worktree and shared_stash
    return dict(path=str(path), head=head, branch=branch, dirty=dirty, index_only=index_only, ignored=ignored,
                stashes=stashes, shared_stash=shared_stash, published=published, merged=merged, reflog=reflog,
                linked_worktrees=linked,
                worktree=worktree, common=str(common),
                remote=git(path, 'remote', 'get-url', 'origin', check=False).stdout.strip())


GIT_OPERATIONS = ('rebase-merge', 'rebase-apply', 'MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'BISECT_LOG',
                  'sequencer')


def in_progress(admin):
    return any((admin / name).exists() for name in GIT_OPERATIONS)


def remove_abandoned(source, common, verify, archived, unchanged):
    import uuid
    admin = Path(git(source, 'rev-parse', '--path-format=absolute', '--git-dir'))
    binding = check_admin(source, common, admin)
    token = 'coldcleaner removing ' + uuid.uuid4().hex
    try:
        with open(admin / 'locked', 'x') as lock:
            lock.write(token)
    except FileExistsError:
        raise ValueError('worktree is locked') from None
    quarantine = source.with_name('.' + source.name + '.coldcleaner-removing-' + uuid.uuid4().hex)
    retired = admin.with_name('.' + admin.name + '.coldcleaner-removing-' + uuid.uuid4().hex)
    try:
        os.rename(source, quarantine)
        moved = False
        try:
            check_unused(source, quarantine)
            snapshot = fingerprint(admin)
            unchanged(quarantine)
            verify(quarantine)
            archived()
            check_holds_above(source)
            if check_admin(source, common, admin, token) != binding:
                raise ValueError('worktree admin folder changed before removal')
            os.rename(admin, retired)
            moved = True
            check_unused(source, quarantine, admin, retired)
            if fingerprint(retired) != snapshot:
                raise ValueError('Git proof changed before removal')
        except Exception:
            if moved:
                os.rename(retired, admin)
            os.rename(quarantine, source)
            raise
    except Exception:
        if (admin / 'locked').is_file() and (admin / 'locked').read_text() == token:
            (admin / 'locked').unlink()
        raise
    delete(quarantine)
    delete(retired)


def fingerprint(folder):
    return sorted((str(item.relative_to(folder)), item.is_dir() or hashlib.sha256(item.read_bytes()).hexdigest())
                  for item in folder.rglob('*'))


def check_admin(source, common, admin, token=None):
    if admin.parent != common / 'worktrees':
        raise ValueError('worktree admin folder is outside the repository')
    lock = admin / 'locked'
    if token is None and lock.exists() or token is not None and lock.read_text() != token:
        raise ValueError('worktree is locked')
    if in_progress(admin):
        raise ValueError('Git operation in progress')
    binding = (admin / 'gitdir').read_text().strip()
    if Path(binding).resolve() != (source / '.git').resolve():
        raise ValueError('worktree admin folder belongs to another worktree')
    return binding


def check_unused(*paths):
    keys = [os.path.realpath(path) for path in paths]
    for reference in references():
        reference = os.path.realpath(reference)
        if any(reference == key or reference.startswith(key.rstrip(os.sep) + os.sep) for key in keys):
            raise ValueError('running process uses ' + reference)


def own_config_fails(path):
    env = {key: value for key, value in os.environ.items() if key not in ('GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS')}
    result = subprocess.run(['git', '-C', str(path), 'worktree', 'list', '--porcelain'], capture_output=True, text=True,
                            env={**env, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull})
    return bool(BAD_CONFIG.match(result.stderr.strip()))


def discover(roots):
    found = {}
    errors, notes = [], []
    for configured in roots:
        root = os.path.expandvars(os.path.expanduser(configured))
        if not os.path.isdir(root):
            continue
        for base, dirs, files in os.walk(root, onerror=lambda e: notes.append('Unreadable, skipped: ' + str(e.filename) + ': ' + str(e.strerror))
                                         if isinstance(e, PermissionError) else errors.append(str(e))):
            if '.git' in dirs or '.git' in files:
                try:
                    result = git(base, 'worktree', 'list', '--porcelain')
                except RuntimeError as exc:
                    if NOT_A_REPOSITORY.match(str(exc)):
                        notes.append('Not a repository, skipped: ' + base + ': ' + str(exc))
                    elif BAD_CONFIG.match(str(exc)) and own_config_fails(base):
                        notes.append('Git cannot read this repository, skipped: ' + base + ': ' + str(exc))
                    else:
                        errors.append(base + ': ' + str(exc))
                    dirs[:] = [d for d in dirs if d != '.git']
                    continue
                found.setdefault(os.path.normpath(base), configured)
                for line in result.splitlines():
                    owner = next((r for r in roots if contained(line[9:], r)), None) if line.startswith('worktree ') else None
                    if owner is not None:
                        found.setdefault(os.path.normpath(line[9:]), owner)
                dirs[:] = []
            else:
                dirs[:] = [d for d in dirs if d not in ('node_modules', '.venv', 'venv', '.git', '__pycache__')
                           and not os.path.islink(os.path.join(base, d))]
    paths = sorted(p for p in found if (Path(p) / '.git').is_file())
    clones = sorted(p for p in found if (Path(p) / '.git').is_dir())
    return dict(paths=paths, clones=clones, roots=found, errors=errors, notes=notes)


def unpublished(path, commits, published):
    if not commits:
        return set()
    known = published & set(git(path, 'for-each-ref', '--format=%(objectname)').splitlines())
    result = git(path, 'rev-list', *commits, '--not', *known, '--', check=False)
    if result.returncode:
        return set(commits)
    return set(result.stdout.split()) & set(commits)


def clone_proof(path, listing):
    published = set(line.split()[0] for line in listing.splitlines() if len(line.split()) == 2)
    commits, unique = {}, []
    for line in git(path, 'for-each-ref', '--format=%(objectname) %(objecttype) %(refname)').splitlines():
        sha, kind, ref = line.split(' ', 2)
        if ref == 'refs/stash' or sha in published:
            continue
        if kind == 'commit':
            commits.setdefault(sha, []).append(ref)
        else:
            unique.append(ref)
    missing = unpublished(path, list(commits), published)
    unique += sorted(ref for sha in missing for ref in commits[sha])
    history = set()
    for ref in ['HEAD', *git(path, 'for-each-ref', '--format=%(refname)', 'refs/heads/').splitlines()]:
        history.update(git(path, 'reflog', 'show', '--format=%H', ref, '--').split())
    return dict(unique_refs=unique, reflog=sorted(unpublished(path, sorted(history), published)))


def main(request):
    op = request['operation']
    path = request.get('path')
    if op == 'batch':
        results, rejected = [], set()
        activity = request.get('activity')
        activity_paths = ActivityPaths() if activity is not None else None
        for item in request['requests']:
            if item['operation'] not in ('guard', 'context', 'repositories', 'repo'):
                raise ValueError('batch only runs read-only checks')
            if item['path'] in rejected:
                results.append(dict(skipped=True))
                continue
            try:
                if item['operation'] == 'guard' and 'activity' not in item:
                    result = guard(item['path'], item.get('days', 0), activity, item.get('protected', ()),
                                   item.get('approval', False), activity_paths, item.get('broad', ()))
                else:
                    result = main(item)
                results.append(dict(result=result))
            except Exception as error:
                results.append(dict(error=str(error), value=isinstance(error, ValueError)))
                rejected.add(item['path'])
        return results
    if op == 'discover':
        return discover(request['roots'])
    if op == 'expand':
        import glob
        found = {}
        for pattern in request['patterns']:
            for match in glob.glob(expanded(pattern)):
                if pattern in request.get('children', []):
                    if Path(match).is_symlink() or not Path(match).is_dir():
                        continue
                    candidates = [str(child) for child in Path(match).iterdir()]
                else:
                    candidates = [match]
                for p in candidates:
                    found.setdefault(p, []).append(pattern)
        keys = {p: real_key(p) for p in found}
        nested = lambda a, b: a == b or a.startswith(b.rstrip(os.sep) + os.sep) or b.startswith(a.rstrip(os.sep) + os.sep)
        related = {p: list(dict.fromkeys(found[p] + [pattern for q in found if nested(keys[p], keys[q])
                                                     for pattern in found[q]])) for p in found}
        exclude = request.get('exclude', {})
        return {p: patterns for p, patterns in sorted(related.items())
                if not excluded(p, [item for pattern in patterns for item in exclude.get(pattern, [])])}
    if op == 'repo':
        return repo(path, request.get('listing', ''), request.get('stub_ok', False), request.get('abandoned', False))
    if op == 'clone':
        return clone_proof(path, request['listing'])
    if op == 'context':
        parent = path if Path(path).is_dir() else str(Path(path).parent)
        result = git(parent, 'rev-parse', '--show-toplevel', check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    if op == 'repositories':
        found = []
        if Path(path).is_dir():
            root = extended(path)
            for base, dirs, files in os.walk(root, onerror=lambda e: (_ for _ in ()).throw(e)):
                if request.get('reject_bare') and 'head' in {name.casefold() for name in files} and 'objects' in {name.casefold() for name in dirs}:
                    raise ValueError('Git repositories require archive_before_delete; use the clone or worktree tier')
                if '.git' in dirs or '.git' in files:
                    found.append(path + base[len(root):])
                dirs[:] = [name for name in dirs if name != '.git']
        return found
    if op == 'unlisted':
        return unlisted(request['roots'], request['covered'], request['skip'], request['seconds'], request.get('state'), request.get('save', False))
    if op == 'sizes':
        deadline = time.monotonic() + request['seconds']
        return [measure(item, deadline) for item in request['paths']]
    if op == 'allowed':
        return locally_allowed(path, request['worktree'])
    if op == 'guard':
        return guard(path, request.get('days', 0), request.get('activity'), request.get('protected', ()), request.get('approval', False),
                     broad=request.get('broad', ()))
    if op == 'activity':
        return dict(**workspaces(), references=references())
    if op == 'manifest':
        return tree(path, True)
    if op == 'bundle':
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory(prefix='coldcleaner-head-') as directory:
            bundle = Path(directory) / 'head.bundle'
            source = Path(directory) / 'source.git'
            git(directory, 'init', '-q', '--bare', '--object-format=' + git(path, 'rev-parse', '--show-object-format'), str(source))
            common = git(path, 'rev-parse', '--path-format=absolute', '--git-common-dir')
            (source / 'objects/info/alternates').write_text(str(Path(common) / 'objects') + '\n')
            git(source, 'update-ref', '--no-deref', 'HEAD', git(path, 'rev-parse', '--verify', 'HEAD^{commit}'))
            for commit in request.get('reflog', []):
                git(source, 'update-ref', reflog_ref(commit), commit + '^{commit}')
            git(source, 'bundle', 'create', str(bundle), 'HEAD', *map(reflog_ref, request.get('reflog', [])))
            with bundle.open('rb') as stream:
                print(json.dumps(dict(sha256=sha256_hex(stream))), flush=True)
            with bundle.open('rb') as stream:
                shutil.copyfileobj(stream, sys.stdout.buffer)
        return None
    if op == 'restore-git':
        import shutil
        import tempfile
        target = Path(path)
        pointer = target / '.git'
        if not pointer.is_file() or pointer.is_symlink():
            raise ValueError('restored worktree pointer is missing or unsafe')
        with tempfile.TemporaryDirectory(prefix='coldcleaner-head-') as directory:
            bundle = Path(directory) / 'head.bundle'
            with bundle.open('xb') as output:
                shutil.copyfileobj(sys.stdin.buffer, output)
            with bundle.open('rb') as stream:
                if sha256_hex(stream) != request['sha256']:
                    raise ValueError('Git recovery bundle SHA-256 mismatch')
            pointer.unlink()
            git(path, 'init', '--object-format=' + object_format(request['head']))
            git(path, 'fetch', str(bundle), 'HEAD')
            if git(path, 'rev-parse', 'FETCH_HEAD') != request['head']:
                raise ValueError('Git recovery head differs')
            if request.get('reflog'):
                git(path, 'fetch', str(bundle), *(f'{reflog_ref(c)}:{reflog_ref(c)}' for c in request['reflog']))
            if request['branch']:
                git(path, 'symbolic-ref', 'HEAD', 'refs/heads/' + request['branch'])
            git(path, 'update-ref', '--no-deref', 'HEAD', request['head']) if not request['branch'] else git(path, 'update-ref', 'HEAD', request['head'])
            git(path, 'read-tree', request['head'])
            if request['remote']:
                git(path, 'remote', 'add', 'origin', request['remote'])
        return dict(restored_git=path)
    if op == 'tar':
        path = extended(path)
        with tarfile.open(fileobj=sys.stdout.buffer, mode='w|', dereference=True) as archive:
            archive.add(path, arcname=Path(path).name)
        return None
    if op == 'restore-stage':
        import tempfile
        target = Path(path)
        if not target.is_absolute() or '..' in target.parts or target in (Path(target.anchor), Path.home()):
            raise ValueError('invalid restore destination')
        if os.path.lexists(target):
            raise FileExistsError('restore destination already exists')
        target.parent.mkdir(parents=True, exist_ok=True)
        return tempfile.mkdtemp(dir=target.parent, prefix='.coldcleaner-restore-')
    if op == 'restore-publish':
        target = Path(request['to'])
        if os.path.lexists(target):
            raise FileExistsError('restore destination already exists')
        os.rename(path, target)
        return dict(restored=str(target))
    if op == 'restore-cleanup':
        import shutil
        if not Path(path).name.startswith('.coldcleaner-restore-'):
            raise ValueError('not a restore staging folder: ' + path)
        shutil.rmtree(path)
        return None
    if op == 'restore':
        import shutil
        import tempfile
        target = Path(path)
        if not target.is_absolute() or '..' in target.parts or target in (Path(target.anchor), Path.home()):
            raise ValueError('invalid restore destination')
        if os.path.lexists(target):
            raise FileExistsError('restore destination already exists')
        target.parent.mkdir(parents=True, exist_ok=True)
        expected = request['manifest']
        roots = {PurePosixPath(name).parts[0] for name in expected}
        if len(roots) != 1:
            raise ValueError('invalid archive root')
        root = roots.pop()
        selected = request.get('member')
        if selected is not None and selected.rstrip('/') not in expected:
            raise ValueError('member is not in the archive')
        wanted = {name: digest for name, digest in expected.items() if selected is None or
                  name == selected.rstrip('/') or name.startswith(selected.rstrip('/') + '/')}
        with tempfile.TemporaryDirectory(dir=target.parent, prefix='.coldcleaner-restore-') as staging:
            found = set()
            metadata = []
            with tarfile.open(fileobj=sys.stdin.buffer, mode='r|') as archive:
                for item in archive:
                    name = item.name.rstrip('/')
                    member_path = PurePosixPath(name)
                    if member_path.is_absolute() or '..' in member_path.parts or '\\' in name or member_path.parts[:1] != (root,):
                        raise ValueError('unsafe archive path')
                    if name not in expected or name in found or not (item.isdir() or item.isfile()):
                        raise ValueError('unexpected archive member')
                    found.add(name)
                    if name not in wanted:
                        continue
                    metadata.append(item)
                    destination = Path(staging).joinpath(*member_path.parts)
                    if item.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        digest = hashlib.sha256()
                        with archive.extractfile(item) as source, destination.open('xb') as output:
                            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                                output.write(chunk); digest.update(chunk)
                            output.flush(); os.fsync(output.fileno())
                        if digest.hexdigest() != wanted[name]:
                            raise ValueError('restore SHA-256 mismatch')
            if found != set(expected) or not set(wanted) <= found:
                raise ValueError('incomplete archive')
            source = Path(staging) / root
            for item in reversed(metadata):
                destination = Path(staging).joinpath(*PurePosixPath(item.name.rstrip('/')).parts)
                os.chmod(destination, item.mode & 0o777)
                os.utime(destination, (item.mtime, item.mtime))
                security = request.get('security', {}).get(item.name.rstrip('/'))
                if security is not None:
                    if os.name == 'nt':
                        windows_security(destination, security)
                    else:
                        os.chown(destination, security['uid'], security['gid'])
                        os.chmod(destination, security['mode'])
                        os.utime(destination, ns=(security['mtime_ns'], security['mtime_ns']))
            if os.path.lexists(target):
                raise FileExistsError('restore destination already exists')
            os.rename(source, target)
        return dict(restored=str(target))
    if op == 'remove':
        locally_allowed(path, bool(request.get('head')) or request.get('clone', False))
        current = guard(path, request.get('days', 0), protected=request.get('protected', ()), approval=request.get('digest') is not None,
                        broad=request.get('broad', ()))
        if request.get('digest') is not None and current['digest'] != request['digest']:
            raise ValueError(APPROVAL_STALE)
        if excluded(path, request.get('exclude', ())):
            raise ValueError('excluded by rules')
        def verify(source):
            if request.get('manifest') is None and request.get('security') is None:
                return
            current = tree(source, True)
            for key, reason in (('manifest', 'source changed after verified NAS copy'),
                                ('security', 'source security changed after verified NAS copy')):
                actual = {Path(path).name + name[len(source.name):]: value for name, value in current[key].items()}
                if request.get(key) is not None and actual != request[key]:
                    raise ValueError(reason)
        def archived():
            keep = request.get('keep')
            if keep and (not os.path.isfile(keep['file']) or os.path.getsize(keep['file']) != keep['bytes']
                         or keep.get('mount') and not os.path.ismount(keep['mount'])):
                raise ValueError('verified archive is no longer present')
        branch_removed = False
        recovery = {}
        abandoned = request.get('abandoned', False)
        if abandoned and (request.get('digest') is None or request.get('manifest') is None):
            raise ValueError('abandoned work needs an approved item and a verified NAS copy')
        if request.get('head'):
            state = repo(path, request['listing'], abandoned=abandoned)
            if (state['head'] != request['head'] or state['branch'] != request['branch']
                    or state['remote'] != request['remote'] or state['stashes']
                    or abandoned and (state['index_only'] or state['shared_stash'])
                    or not abandoned and (state['dirty'] or not state['published'])
                    or state['ignored'] and request.get('manifest') is None
                    or state['reflog'] and (request.get('manifest') is None
                                            or not set(state['reflog']) <= set(request.get('reflog') or ()))):
                raise ValueError('Git proof changed before removal')
            recovery = {key: state[key] for key in ('head', 'branch', 'remote', 'merged')}
            branch = state['branch']
            verify(Path(path))
            branches = git(path, 'worktree', 'list', '--porcelain').splitlines()
            keep_branch = abandoned or branches.count('branch refs/heads/' + branch) > 1
            def unchanged(source):
                current = repo(source, request['listing'], abandoned=True)
                if (current['head'] != state['head'] or current['branch'] != state['branch'] or current['shared_stash']
                        or current['index_only'] or not set(current['reflog']) <= set(request.get('reflog') or ())):
                    raise ValueError('Git proof changed before removal')
            if abandoned:
                remove_abandoned(Path(path), Path(state['common']), verify, archived, unchanged)
            else:
                archived()
                tree(Path(path))
                check_holds_above(Path(path))
                git(state['common'], 'worktree', 'remove', '--', path)
            if branch and not keep_branch:
                subprocess.run(['git', '--git-dir', state['common'], 'update-ref', '-d',
                                'refs/heads/' + branch, state['head']], check=True, capture_output=True)
                branch_removed = True
        else:
            import uuid
            source = Path(path)
            verify(source)
            quarantine = source.with_name('.' + source.name + '.coldcleaner-removing-' + uuid.uuid4().hex)
            os.rename(source, quarantine)
            try:
                verify(quarantine)
                archived()
                check_holds_above(source)
            except Exception:
                os.rename(quarantine, source)
                raise
            delete(quarantine)
        return dict(removed=path, branch_removed=branch_removed, **recovery)
    raise ValueError('unknown operation')
