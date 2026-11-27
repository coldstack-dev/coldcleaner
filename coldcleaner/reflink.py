"""Copy-on-write reflink deduplication across active Git worktrees."""
from collections import Counter
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import time

try:
    import fcntl
except ImportError:
    fcntl = None


MIN_BYTES = 4096
CHUNK_SIZE = 1024 * 1024
DEDUPE_MAX_CHUNK = 16 * 1024 * 1024
FIDEDUPERANGE = 0xC0189436
FILE_DEDUPE_RANGE_SAME = 0
FILE_DEDUPE_RANGE_DIFFERS = 1
FS_IOC_FIEMAP = 0xC020660B
FIEMAP_MAX_OFFSET = (1 << 64) - 1
FIEMAP_BATCH = 32
FIEMAP_EXTENT_LAST = 0x00000001
FIEMAP_EXTENT_UNKNOWN = 0x00000002
FIEMAP_EXTENT_DELALLOC = 0x00000004
FIEMAP_EXTENT_DATA_INLINE = 0x00000200
FIEMAP_EXTENT_DATA_TAIL = 0x00000400
FIEMAP_UNSAFE_FLAGS = (
    FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC | FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_DATA_TAIL
)
LINUX_COW_FS = frozenset(('btrfs', 'xfs', 'bcachefs', 'ocfs2'))
UNSUPPORTED_ERRNOS = frozenset(
    getattr(errno, name)
    for name in ('EOPNOTSUPP', 'ENOTSUP', 'ENOSYS', 'EXDEV', 'EINVAL')
    if hasattr(errno, name)
)
PRUNE_DISCOVER = frozenset(('node_modules', '.venv', 'venv', '.git', '__pycache__'))
PERSONAL_FOLDERS = (
    'Documents', 'Desktop', 'Pictures', 'Library',
    'iCloud Drive', 'iCloudDrive', 'Google Drive',
)
SYSTEM_PROTECTED = ('/etc', '/usr', '/System')
LEASE = '.coldcleaner-lease'
LEASE_TIME = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', re.ASCII)
APFS_DRY_RUN_NOTE = (
    'macOS APFS lacks kernel-atomic in-place extent deduplication (FIDEDUPERANGE); '
    'dry-run reports duplicates only and --apply does not overwrite existing files'
)
APFS_APPLY_NOTE = (
    'macOS APFS lacks kernel-atomic in-place extent deduplication (FIDEDUPERANGE); '
    'refusing to overwrite live files via clonefile+replace to avoid concurrent-save races and directory ACL inheritance'
)
TEXT_LIMIT = 20


class UnsupportedReflinkError(OSError):
    pass


class FileChangedError(OSError):
    pass


class LeasedError(OSError):
    pass


def _git(path, *args):
    env = dict(
        os.environ,
        GIT_OPTIONAL_LOCKS='0',
        GIT_TERMINAL_PROMPT='0',
        GIT_NO_REPLACE_OBJECTS='1',
        GIT_NO_LAZY_FETCH='1',
    )
    result = subprocess.run(['git', '-C', str(path), *args], capture_output=True, env=env)
    if result.returncode:
        detail = result.stderr.decode(errors='replace').strip()
        raise RuntimeError(detail or 'git command failed')
    return result.stdout


def _filesystem_types(path):
    target = Path(os.path.realpath(path))
    while not target.exists() and target != target.parent:
        target = target.parent
    if sys.platform == 'darwin':
        output = subprocess.run(['/sbin/mount'], capture_output=True, text=True, check=True, timeout=30).stdout
        mounts = []
        for line in output.splitlines():
            match = re.fullmatch(r'.+? on (/.*) \((\w+)(?:, .*)?\)', line)
            if match:
                mounts.append((Path(match.group(1)), match.group(2)))
    elif sys.platform.startswith('linux'):
        mounts = []
        for line in Path('/proc/self/mountinfo').read_text(encoding='utf-8').splitlines():
            fields, kind = line.split(' - ', 1)
            point = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), fields.split()[4])
            mounts.append((Path(point), kind.split()[0]))
    else:
        return set()
    covering = [(point, kind) for point, kind in mounts if target.is_relative_to(point)]
    if not covering:
        return set()
    closest = max((point for point, _ in covering), key=lambda p: len(p.parts))
    return {kind for point, kind in covering if point == closest}


def detect_backend(path):
    if sys.platform.startswith('linux'):
        if fcntl is None:
            return 'unsupported'
        try:
            fs_types = _filesystem_types(path)
        except OSError:
            return 'unsupported'
        return 'linux-fideduperange' if fs_types & LINUX_COW_FS else 'unsupported'
    if sys.platform == 'darwin':
        try:
            fs_types = _filesystem_types(path)
        except (OSError, subprocess.SubprocessError):
            return 'unsupported'
        return 'apfs-no-atomic-inplace' if 'apfs' in fs_types else 'unsupported'
    return 'unsupported'


def _stat_key(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _resolve_paths(paths):
    resolved = []
    for raw in paths:
        if not raw:
            continue
        expanded = os.path.expandvars(os.path.expanduser(str(raw)))
        resolved.append(Path(os.path.realpath(expanded)))
    return resolved


def _add_protected(locations, raw_path):
    expanded = os.path.expandvars(os.path.expanduser(str(raw_path)))
    abs_path = Path(os.path.abspath(expanded))
    locations.add(abs_path)
    try:
        locations.add(Path(os.path.realpath(expanded)))
    except OSError:
        pass
    try:
        locations.add(abs_path.resolve(strict=False))
    except OSError:
        pass


def _protected_roots(extra=()):
    locations = set()
    for system_path in SYSTEM_PROTECTED:
        _add_protected(locations, system_path)
    home_raw = Path.home()
    home_variants = {home_raw}
    try:
        home_variants.add(Path(os.path.realpath(str(home_raw))))
    except OSError:
        pass
    for home in home_variants:
        for name in PERSONAL_FOLDERS:
            _add_protected(locations, home / name)
        try:
            for entry in os.scandir(home):
                if entry.name.casefold().startswith('onedrive'):
                    _add_protected(locations, entry.path)
        except OSError:
            pass
    for item in extra:
        if item:
            _add_protected(locations, item)
    return tuple(locations)


def _in_roots(path, resolved_roots):
    real = Path(os.path.realpath(path))
    return any(real.is_relative_to(root) for root in resolved_roots)


def _is_protected(path, protected_roots):
    abs_p = Path(os.path.abspath(path))
    real_p = Path(os.path.realpath(path))
    return any(abs_p.is_relative_to(prot) or real_p.is_relative_to(prot) for prot in protected_roots)


def _has_keep_local(path):
    current = Path(os.path.realpath(path))
    while True:
        if (current / '.keep-local').exists():
            return True
        if current == current.parent:
            return False
        current = current.parent


def _lease_active(lease_path, now=None):
    if not os.path.lexists(lease_path):
        return False
    try:
        if not stat.S_ISREG(os.lstat(lease_path).st_mode):
            return True
        text = Path(lease_path).read_text(encoding='utf-8').strip()
        if not LEASE_TIME.fullmatch(text):
            return True
        expiry = datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
    except (OSError, ValueError):
        return True
    current = time.time() if now is None else now
    return expiry > current


def _folder_has_active_lease(folder, now=None):
    direct = os.path.join(folder, LEASE)
    if os.path.lexists(direct) and _lease_active(direct, now=now):
        return True
    try:
        names = os.listdir(folder)
    except OSError:
        return True
    for name in names:
        if name.casefold() == LEASE and _lease_active(os.path.join(folder, name), now=now):
            return True
    return False


def _has_active_lease_above(path, now=None):
    current = Path(os.path.realpath(path))
    while True:
        if _folder_has_active_lease(str(current), now=now):
            return True
        if current == current.parent:
            return False
        current = current.parent


def _open_write_inodes():
    inodes = set()
    if sys.platform.startswith('linux'):
        me = str(os.getpid())
        try:
            entries = os.listdir('/proc')
        except OSError:
            return inodes
        for pid in entries:
            if not pid.isdigit() or pid == me:
                continue
            fd_dir = f'/proc/{pid}/fd'
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue
            for fd in fds:
                try:
                    with open(f'/proc/{pid}/fdinfo/{fd}', 'r', encoding='utf-8') as stream:
                        flags = None
                        for line in stream:
                            if line.startswith('flags:'):
                                flags = int(line.split(':', 1)[1].strip(), 8)
                                break
                    if flags is None or (flags & 3) == 0:
                        continue
                    st = os.stat(f'{fd_dir}/{fd}')
                    if stat.S_ISREG(st.st_mode):
                        inodes.add((st.st_dev, st.st_ino))
                except (OSError, ValueError):
                    continue
        return inodes
    if sys.platform == 'darwin':
        try:
            result = subprocess.run(
                ['lsof', '-nP', '-u', str(os.geteuid()), '-F', 'an'],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return inodes
        access = ''
        for line in result.stdout.splitlines():
            if not line:
                continue
            tag, value = line[0], line[1:]
            if tag == 'a':
                access = value
            elif tag == 'n' and access in ('w', 'u') and value.startswith('/'):
                try:
                    st = os.lstat(value)
                    if stat.S_ISREG(st.st_mode):
                        inodes.add((st.st_dev, st.st_ino))
                except OSError:
                    pass
                access = ''
            elif tag == 'f':
                access = ''
    return inodes


def _file_extents(fd):
    if not sys.platform.startswith('linux') or fcntl is None:
        return None
    extents = []
    start = 0
    while True:
        buf = bytearray(32 + FIEMAP_BATCH * 56)
        struct.pack_into('=QQIIII', buf, 0, start, FIEMAP_MAX_OFFSET - start, 0, 0, FIEMAP_BATCH, 0)
        try:
            fcntl.ioctl(fd, FS_IOC_FIEMAP, buf, True)
        except OSError:
            return None
        _, _, _, mapped, _, _ = struct.unpack_from('=QQIIII', buf, 0)
        if mapped == 0:
            break
        last = False
        for index in range(mapped):
            logical, physical, length, _, _, flags, _, _, _ = struct.unpack_from('=QQQQQIIII', buf, 32 + index * 56)
            if (flags & FIEMAP_UNSAFE_FLAGS) or physical == 0:
                return None
            extents.append((logical, physical, length))
            if flags & FIEMAP_EXTENT_LAST:
                last = True
            start = logical + length
        if last or mapped < FIEMAP_BATCH:
            break
    return extents if extents else None


def extents_shared(path_a, st_a, path_b, st_b, backend):
    if st_a.st_dev == st_b.st_dev and st_a.st_ino == st_b.st_ino:
        return True
    if backend != 'linux-fideduperange':
        return False
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    try:
        fd_a = os.open(path_a, flags)
        try:
            ext_a = _file_extents(fd_a)
        finally:
            os.close(fd_a)
        if not ext_a:
            return False
        fd_b = os.open(path_b, flags)
        try:
            ext_b = _file_extents(fd_b)
        finally:
            os.close(fd_b)
        return ext_b == ext_a
    except OSError:
        return False


def _hash_file(path, expected_st):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or _stat_key(before) != _stat_key(expected_st):
            raise FileChangedError('file changed before hashing')
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        if _stat_key(after) != _stat_key(expected_st):
            raise FileChangedError('file changed while hashing')
        return digest.hexdigest()
    finally:
        os.close(fd)


def _fideduperange_ioctl(src_fd, buf):
    fcntl.ioctl(src_fd, FIDEDUPERANGE, buf, True)


def _dedupe_linux(donor, target, donor_st, target_st):
    open_ro = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    open_rw = os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    src_fd = os.open(donor, open_ro)
    try:
        if _stat_key(os.fstat(src_fd)) != _stat_key(donor_st):
            raise FileChangedError('donor changed before dedupe')
        dst_fd = os.open(target, open_rw)
        try:
            dst_cur = os.fstat(dst_fd)
            if not stat.S_ISREG(dst_cur.st_mode) or _stat_key(dst_cur) != _stat_key(target_st):
                raise FileChangedError('target changed before dedupe')
            size = target_st.st_size
            offset = 0
            total_deduped = 0
            while offset < size:
                if _has_active_lease_above(os.path.dirname(target)):
                    raise LeasedError('target leased before dedupe')
                chunk = min(DEDUPE_MAX_CHUNK, size - offset)
                buf = bytearray(24 + 32)
                struct.pack_into('=QQHHI', buf, 0, offset, chunk, 1, 0, 0)
                struct.pack_into('=qQQiI', buf, 24, dst_fd, offset, 0, 0, 0)
                try:
                    _fideduperange_ioctl(src_fd, buf)
                except OSError as exc:
                    if exc.errno in UNSUPPORTED_ERRNOS:
                        raise UnsupportedReflinkError(exc.errno, exc.strerror) from None
                    if exc.errno == getattr(errno, 'ETXTBSY', -1):
                        raise FileChangedError('target busy during dedupe') from None
                    raise
                _, _, bytes_deduped, status, _ = struct.unpack_from('=qQQiI', buf, 24)
                if status == FILE_DEDUPE_RANGE_DIFFERS:
                    raise FileChangedError('file changed concurrently during kernel dedupe')
                if status < 0:
                    err = -status
                    if err in UNSUPPORTED_ERRNOS:
                        raise UnsupportedReflinkError(err, os.strerror(err))
                    if err == getattr(errno, 'ETXTBSY', -1):
                        raise FileChangedError('target busy during dedupe')
                    if err in (errno.EACCES, errno.EPERM):
                        raise PermissionError(err, os.strerror(err))
                    raise OSError(err, os.strerror(err))
                if status != FILE_DEDUPE_RANGE_SAME:
                    raise OSError(f'unexpected FIDEDUPERANGE status: {status}')
                if bytes_deduped == 0:
                    break
                step = min(bytes_deduped, chunk)
                total_deduped += step
                offset += step
            return total_deduped
        finally:
            os.close(dst_fd)
    finally:
        os.close(src_fd)


def reflink_replace(donor, target, donor_st, target_st, backend):
    if donor_st.st_dev != target_st.st_dev:
        raise UnsupportedReflinkError(errno.EXDEV, 'cross-device reflink refused')
    if not (stat.S_ISREG(donor_st.st_mode) and stat.S_ISREG(target_st.st_mode)):
        raise ValueError('reflink requires regular files')
    if donor_st.st_size != target_st.st_size:
        raise FileChangedError('size mismatch before reflink')
    if backend == 'linux-fideduperange':
        return _dedupe_linux(donor, target, donor_st, target_st)
    raise UnsupportedReflinkError(errno.ENOTSUP, 'backend does not support kernel-atomic in-place deduplication')


def _parse_worktree_list(raw):
    worktrees = []
    block = {}
    for line in raw.decode(errors='surrogateescape').splitlines() + ['']:
        if not line:
            path = block.get('worktree')
            if path and not block.get('bare') and not block.get('prunable') and os.path.isdir(path):
                worktrees.append(path)
            block = {}
        elif line.startswith('worktree '):
            block['worktree'] = line[9:]
        elif line == 'bare':
            block['bare'] = True
        elif line.startswith('prunable'):
            block['prunable'] = True
    return worktrees


def discover_worktree_groups(roots):
    groups = {}
    errors = []
    seen_dirs = set()

    def register(repo_dir):
        real_repo = os.path.realpath(repo_dir)
        if real_repo in seen_dirs:
            return
        try:
            common_raw = _git(repo_dir, 'rev-parse', '--git-common-dir').decode(errors='surrogateescape').strip()
            common = os.path.realpath(os.path.join(repo_dir, common_raw))
            listing = _git(repo_dir, 'worktree', 'list', '--porcelain')
        except RuntimeError as exc:
            errors.append(f'{repo_dir}: {exc}')
            return
        bucket = groups.setdefault(common, {})
        for wt in _parse_worktree_list(listing):
            real_wt = os.path.realpath(wt)
            seen_dirs.add(real_wt)
            bucket.setdefault(real_wt, wt)

    for raw_root in roots:
        root = os.path.abspath(os.path.expandvars(os.path.expanduser(str(raw_root))))
        if not os.path.isdir(root):
            errors.append(f'path is not a directory: {raw_root}')
            continue
        if os.path.lexists(os.path.join(root, '.git')):
            register(root)
            continue
        for base, dirs, files in os.walk(root, followlinks=False):
            if '.git' in dirs or '.git' in files:
                register(base)
                dirs[:] = []
                continue
            dirs[:] = [
                name for name in sorted(dirs)
                if name not in PRUNE_DISCOVER and not os.path.islink(os.path.join(base, name))
            ]

    ordered = []
    for common in sorted(groups):
        paths = list(groups[common].values())
        paths.sort(key=lambda p: (0 if os.path.isdir(os.path.join(p, '.git')) else 1, p))
        ordered.append(paths)
    return ordered, errors


def dirty_paths(worktree):
    raw = _git(worktree, 'status', '--porcelain=v1', '-z', '--untracked-files=all')
    dirty = set()
    tokens = raw.split(b'\0')
    index = 0
    while index < len(tokens):
        entry = tokens[index]
        if not entry:
            index += 1
            continue
        status = entry[:2]
        path = os.fsdecode(entry[3:]).rstrip('/')
        if path:
            dirty.add(path)
        if status[:1] in (b'R', b'C') or status[1:2] in (b'R', b'C'):
            index += 1
            if index < len(tokens) and tokens[index]:
                other = os.fsdecode(tokens[index]).rstrip('/')
                if other:
                    dirty.add(other)
        index += 1
    return dirty


def _is_dirty(rel, dirty):
    if not dirty:
        return False
    if rel in dirty:
        return True
    parts = rel.split('/')
    for end in range(1, len(parts)):
        if '/'.join(parts[:end]) in dirty:
            return True
    return False


def _scan_worktree(worktree, dirty, open_writes, min_bytes, skipped, by_rel, protected_roots):
    euid = os.geteuid() if hasattr(os, 'geteuid') else None

    def walk_dir(directory, prefix):
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError:
            skipped['unreadable'] += 1
            return
        for entry in entries:
            name = entry.name
            if name == '.git':
                skipped['git_metadata'] += 1
                continue
            if name.casefold() == LEASE:
                skipped['leased'] += 1
                continue
            rel = name if not prefix else f'{prefix}/{name}'
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                skipped['unreadable'] += 1
                continue
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                skipped['symlink'] += 1
                continue
            if _is_protected(entry.path, protected_roots):
                skipped['protected'] += 1
                continue
            if stat.S_ISDIR(mode):
                if os.path.lexists(os.path.join(entry.path, '.git')):
                    skipped['nested_git_repo'] += 1
                    continue
                if os.path.lexists(os.path.join(entry.path, '.keep-local')) or os.path.lexists(
                    os.path.join(entry.path, '.obsidian')
                ):
                    skipped['protected'] += 1
                    continue
                if _folder_has_active_lease(entry.path):
                    skipped['leased'] += 1
                    continue
                walk_dir(entry.path, rel)
                continue
            if not stat.S_ISREG(mode):
                skipped['special_file'] += 1
                continue
            if mode & (stat.S_ISUID | stat.S_ISGID):
                skipped['special_mode'] += 1
                continue
            if euid is not None and st.st_uid != euid:
                skipped['other_owner'] += 1
                continue
            if _is_dirty(rel, dirty):
                skipped['dirty'] += 1
                continue
            if (st.st_dev, st.st_ino) in open_writes:
                skipped['open_for_write'] += 1
                continue
            if st.st_size == 0 or st.st_size < min_bytes:
                skipped['below_min_size'] += 1
                continue
            by_rel.setdefault(rel, []).append((entry.path, st, worktree))

    walk_dir(worktree, '')


def dedupe(
    roots,
    *,
    apply=False,
    min_bytes=MIN_BYTES,
    protected=(),
    backend_detector=None,
):
    detect = backend_detector or detect_backend
    resolved_roots = _resolve_paths(roots)
    protected_roots = _protected_roots(protected)
    groups, errors = discover_worktree_groups(roots)
    skipped = Counter()
    candidates = []
    notes = []
    device_backends = {}
    candidate_files = 0
    relinked_files = 0
    reclaimable_bytes = 0
    reclaimed_bytes = 0
    worktrees_scanned = 0
    multi_groups = 0

    def backend_for(path, dev):
        if dev not in device_backends:
            device_backends[dev] = detect(path)
        return device_backends[dev]

    if not roots:
        notes.append('no roots configured')
    for raw_root in roots:
        expanded = os.path.abspath(os.path.expandvars(os.path.expanduser(str(raw_root))))
        if os.path.isdir(expanded):
            try:
                backend_for(expanded, os.stat(expanded).st_dev)
            except OSError:
                pass
    if not device_backends:
        try:
            cwd = os.getcwd()
            backend_for(cwd, os.stat(cwd).st_dev)
        except OSError:
            pass

    open_writes = _open_write_inodes()

    for group in groups:
        eligible = []
        for wt in group:
            if not _in_roots(wt, resolved_roots):
                skipped['outside_roots'] += 1
                continue
            if _is_protected(wt, protected_roots) or _has_keep_local(wt) or os.path.lexists(
                os.path.join(wt, '.obsidian')
            ):
                skipped['protected'] += 1
                continue
            if _has_active_lease_above(wt):
                skipped['leased'] += 1
                continue
            eligible.append(wt)
        worktrees_scanned += len(eligible)
        if len(eligible) < 2:
            continue
        multi_groups += 1
        by_rel = {}
        for wt in eligible:
            try:
                wt_dirty = dirty_paths(wt)
            except RuntimeError as exc:
                skipped['git_status_failed'] += 1
                errors.append(f'{wt}: {exc}')
                continue
            _scan_worktree(wt, wt_dirty, open_writes, min_bytes, skipped, by_rel, protected_roots)

        for rel in sorted(by_rel):
            entries = by_rel[rel]
            if len(entries) < 2:
                continue
            by_dev = {}
            for item in entries:
                by_dev.setdefault(item[1].st_dev, []).append(item)
            primary_dev = entries[0][1].st_dev
            for dev, dev_entries in by_dev.items():
                if len(dev_entries) < 2:
                    if len(by_dev) > 1 and dev != primary_dev:
                        skipped['cross_device'] += 1
                    continue
                backend = backend_for(dev_entries[0][0], dev)
                if backend == 'unsupported':
                    skipped['unsupported_filesystem'] += len(dev_entries) - 1
                    continue
                if backend == 'apfs-no-atomic-inplace' and apply:
                    skipped['apfs_no_atomic_inplace'] += len(dev_entries) - 1
                    continue
                by_size = {}
                for item in dev_entries:
                    by_size.setdefault(item[1].st_size, []).append(item)
                primary_size = dev_entries[0][1].st_size
                for size, size_entries in by_size.items():
                    if len(size_entries) < 2:
                        if size != primary_size:
                            skipped['content_differs'] += 1
                        continue
                    donors = {}
                    digest_counts = Counter()
                    primary_digest = None
                    for idx, (path, st, _) in enumerate(size_entries):
                        current_backend = device_backends[dev]
                        if current_backend == 'unsupported':
                            skipped['unsupported_filesystem'] += 1
                            continue
                        try:
                            digest = _hash_file(path, st)
                        except (OSError, FileChangedError):
                            skipped['changed_during_scan'] += 1
                            continue
                        if idx == 0:
                            primary_digest = digest
                        digest_counts[digest] += 1
                        if digest not in donors:
                            donors[digest] = (path, st)
                            continue
                        donor_path, donor_st = donors[digest]
                        if extents_shared(donor_path, donor_st, path, st, current_backend):
                            skipped['already_shared'] += 1
                            continue
                        if not apply:
                            candidate_files += 1
                            reclaimable_bytes += st.st_size
                            candidates.append(dict(
                                donor=donor_path,
                                target=path,
                                bytes=st.st_size,
                                sha256=digest,
                                action='would reflink',
                            ))
                            continue
                        if _has_active_lease_above(os.path.dirname(path)):
                            skipped['leased'] += 1
                            continue
                        try:
                            deduped = reflink_replace(donor_path, path, donor_st, st, current_backend)
                        except UnsupportedReflinkError:
                            device_backends[dev] = 'unsupported'
                            skipped['unsupported_filesystem'] += 1
                        except LeasedError:
                            skipped['leased'] += 1
                        except FileChangedError:
                            skipped['changed_during_reflink'] += 1
                        except PermissionError:
                            skipped['permission_denied'] += 1
                        except OSError as exc:
                            errors.append(f'{path}: {exc}')
                        else:
                            if deduped <= 0:
                                skipped['not_deduped'] += 1
                                continue
                            candidate_files += 1
                            relinked_files += 1
                            reclaimable_bytes += deduped
                            reclaimed_bytes += deduped
                            candidates.append(dict(
                                donor=donor_path,
                                target=path,
                                bytes=deduped,
                                sha256=digest,
                                action='reflinked',
                            ))
                    for digest, count in digest_counts.items():
                        if count == 1 and digest != primary_digest:
                            skipped['content_differs'] += 1

    backends_seen = set(device_backends.values())
    if 'linux-fideduperange' in backends_seen:
        backend = 'linux-fideduperange'
        apply_supported = True
        status = 'incomplete' if errors else 'ok'
        if 'unsupported' in backends_seen:
            notes.append('some worktrees are on filesystems without copy-on-write reflink support and were skipped')
    elif 'apfs-no-atomic-inplace' in backends_seen:
        backend = 'apfs-no-atomic-inplace'
        apply_supported = False
        if errors:
            status = 'incomplete'
        elif apply:
            status = 'unsupported'
            notes.append(APFS_APPLY_NOTE)
        else:
            status = 'ok'
            notes.append(APFS_DRY_RUN_NOTE)
    else:
        backend = 'unsupported'
        apply_supported = False
        status = 'incomplete' if errors else 'unsupported'
        if not errors:
            notes.append('filesystem does not support copy-on-write reflinks; no files modified')

    return dict(
        status=status,
        mode='apply' if apply else 'dry-run',
        backend=backend,
        apply_supported=apply_supported,
        min_bytes=min_bytes,
        worktree_groups=multi_groups,
        worktrees_scanned=worktrees_scanned,
        candidate_files=candidate_files,
        relinked_files=relinked_files,
        reclaimable_bytes=reclaimable_bytes,
        reclaimed_bytes=reclaimed_bytes,
        skipped=dict(sorted(skipped.items())),
        candidates=candidates,
        notes=notes,
        errors=errors,
    )


def _format_bytes(value):
    size = float(value)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if size < 1024 or unit == 'TiB':
            return f'{int(size)} B' if unit == 'B' else f'{size:.1f} {unit}'
        size /= 1024
    return f'{value} B'


def render_text(result):
    lines = [f"Mode: {result['mode']} (backend: {result['backend']}, min-bytes: {result['min_bytes']})"]
    if result['status'] == 'unsupported':
        if result['backend'] == 'apfs-no-atomic-inplace':
            lines.append('Status: unsupported (macOS APFS has no atomic in-place dedupe; no files modified)')
        else:
            lines.append('Status: unsupported (filesystem does not support copy-on-write reflinks; no files modified)')
    else:
        lines.append(
            f"Worktree groups: {result['worktree_groups']} ({result['worktrees_scanned']} worktrees scanned)"
        )
        if result['mode'] == 'apply':
            lines.append(
                f"Relinked: {result['relinked_files']} files, {_format_bytes(result['reclaimed_bytes'])} reclaimed"
            )
        else:
            lines.append(
                f"Candidates: {result['candidate_files']} files, {_format_bytes(result['reclaimable_bytes'])} reclaimable"
            )
    if result['skipped']:
        summary = ', '.join(f'{reason}={count}' for reason, count in result['skipped'].items())
        lines.append(f'Skipped: {summary}')
    for note in result['notes']:
        lines.append(f'Note: {note}')
    for error in result['errors']:
        lines.append(f'Error: {error}')
    shown = result['candidates'][:TEXT_LIMIT]
    for item in shown:
        lines.append(f"  {item['action']}  {_format_bytes(item['bytes'])}  {item['target']} <- {item['donor']}")
    extra = len(result['candidates']) - len(shown)
    if extra > 0:
        lines.append(f'  ... and {extra} more')
    if result['mode'] == 'dry-run' and result['candidate_files'] > 0 and result.get('apply_supported', False):
        lines.append('Dry run. Rerun with --apply to deduplicate files with copy-on-write reflinks.')
    return '\n'.join(lines)


REMOTE_RUNNER = '''
request = json.loads(sys.stdin.buffer.readline())
result = dedupe(
    request['roots'],
    apply=request['apply'],
    min_bytes=request['min_bytes'],
    protected=request.get('protected', ()),
)
print(json.dumps(result))
'''


def run_host(host, roots, *, apply=False, min_bytes=MIN_BYTES, protected=()):
    if host.kind != 'posix':
        return dict(
            status='unsupported',
            mode='apply' if apply else 'dry-run',
            backend='unsupported',
            apply_supported=False,
            min_bytes=min_bytes,
            worktree_groups=0,
            worktrees_scanned=0,
            candidate_files=0,
            relinked_files=0,
            reclaimable_bytes=0,
            reclaimed_bytes=0,
            skipped={},
            candidates=[],
            notes=[f'{host.name}: copy-on-write reflinks require Linux Btrfs/XFS (FIDEDUPERANGE); APFS is dry-run report only'],
            errors=[],
        )
    if host.ssh is None:
        return dedupe(roots, apply=apply, min_bytes=min_bytes, protected=protected)
    from . import hosts as hosts_mod
    source = Path(__file__).read_text(encoding='utf-8') + '\n' + REMOTE_RUNNER
    payload = dict(roots=list(roots), apply=bool(apply), min_bytes=int(min_bytes), protected=list(protected))
    completed = hosts_mod.python_run(host, source, payload, timeout=1800)
    return json.loads(completed.stdout.decode('utf-8'))


def run_hosts(config, selected, *, apply=False, min_bytes=MIN_BYTES):
    if len(selected) == 1:
        host = selected[0]
        host_cfg = config['hosts'][host.name]
        roots = host_cfg.get('roots', [])
        protected = host_cfg.get('protected', [])
        result = run_host(host, roots, apply=apply, min_bytes=min_bytes, protected=protected)
        return dict(host=host.name, **result)
    host_results = []
    skipped = Counter()
    candidates = []
    notes = []
    errors = []
    backends = set()
    for host in selected:
        host_cfg = config['hosts'][host.name]
        roots = host_cfg.get('roots', [])
        protected = host_cfg.get('protected', [])
        res = run_host(host, roots, apply=apply, min_bytes=min_bytes, protected=protected)
        host_results.append(dict(name=host.name, **res))
        skipped.update(res['skipped'])
        candidates.extend(dict(host=host.name, **item) for item in res['candidates'])
        notes.extend(f"{host.name}: {n}" for n in res['notes'])
        errors.extend(f"{host.name}: {e}" for e in res['errors'])
        backends.add(res['backend'])
    if 'linux-fideduperange' in backends:
        backend = 'linux-fideduperange'
        apply_supported = True
        status = 'incomplete' if errors else 'ok'
    elif 'apfs-no-atomic-inplace' in backends:
        backend = 'apfs-no-atomic-inplace'
        apply_supported = False
        status = 'incomplete' if errors else ('unsupported' if apply else 'ok')
    else:
        backend = 'unsupported'
        apply_supported = False
        status = 'incomplete' if errors else 'unsupported'
    return dict(
        status=status,
        mode='apply' if apply else 'dry-run',
        backend=backend,
        apply_supported=apply_supported,
        min_bytes=min_bytes,
        worktree_groups=sum(r['worktree_groups'] for r in host_results),
        worktrees_scanned=sum(r['worktrees_scanned'] for r in host_results),
        candidate_files=sum(r['candidate_files'] for r in host_results),
        relinked_files=sum(r['relinked_files'] for r in host_results),
        reclaimable_bytes=sum(r['reclaimable_bytes'] for r in host_results),
        reclaimed_bytes=sum(r['reclaimed_bytes'] for r in host_results),
        skipped=dict(sorted(skipped.items())),
        candidates=candidates,
        notes=notes,
        errors=errors,
        hosts=host_results,
    )
