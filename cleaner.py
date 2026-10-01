"""Remove things: either to the Recycle Bin (recoverable, via the Windows shell with "undo" enabled) or permanently.
Both are only ever called by the GUI for items rated safe, after a confirmation."""
import ctypes
import os
import stat

from scanner import is_link, long_path

FO_DELETE = 3
FOF_ALLOWUNDO = 0x0040          # use the Recycle Bin
FOF_NOERRORUI = 0x0400          # no error pop-ups for files that are in use; we report them ourselves
FOF_WANTNUKEWARNING = 0x4000    # warn if something cannot go to the Recycle Bin and would be deleted for good


class SHFILEOPSTRUCTW(ctypes.Structure):
    if ctypes.sizeof(ctypes.c_void_p) == 4:
        _pack_ = 1
    _fields_ = [('hwnd', ctypes.c_void_p), ('wFunc', ctypes.c_uint), ('pFrom', ctypes.c_void_p), ('pTo', ctypes.c_void_p),
                ('fFlags', ctypes.c_ushort), ('fAnyOperationsAborted', ctypes.c_int), ('hNameMappings', ctypes.c_void_p),
                ('lpszProgressTitle', ctypes.c_wchar_p)]


def recycle(paths):
    """Send `paths` to the Recycle Bin in one shell operation. Returns (ok, user_aborted)."""
    paths = [os.path.abspath(p) for p in paths]
    if not paths:
        return True, False
    raw = ('\0'.join(paths) + '\0\0').encode('utf-16-le')
    buf = ctypes.create_string_buffer(raw, len(raw))       # pFrom is a double-NUL-terminated list
    op = SHFILEOPSTRUCTW()
    op.wFunc = FO_DELETE
    op.pFrom = ctypes.addressof(buf)
    op.fFlags = FOF_ALLOWUNDO | FOF_NOERRORUI | FOF_WANTNUKEWARNING
    op.lpszProgressTitle = 'Disk Detective'
    shell32 = ctypes.windll.shell32
    shell32.SHFileOperationW.argtypes = [ctypes.POINTER(SHFILEOPSTRUCTW)]
    rc = shell32.SHFileOperationW(ctypes.byref(op))
    return rc == 0, bool(op.fAnyOperationsAborted)


def recycle_in_chunks(paths, chunk=800):
    ok, aborted = True, False
    for i in range(0, len(paths), chunk):
        part_ok, part_aborted = recycle(paths[i:i + chunk])
        ok &= part_ok
        if part_aborted:
            return False, True
    return ok, aborted


def _unlink(lp):
    try:
        os.unlink(lp)
    except PermissionError:                  # read-only file: clear the flag and try once more
        os.chmod(lp, stat.S_IWRITE)
        os.unlink(lp)


def _remove(path, failed):
    """Delete one file, link or folder tree. Returns how many items were removed; failures go to `failed`."""
    lp = long_path(path)
    try:
        st = os.lstat(lp)
    except OSError as exc:
        failed.append((path, exc))
        return 0
    removed = 0
    try:
        if stat.S_ISDIR(st.st_mode) and not is_link(st):
            try:
                names = os.listdir(lp)
            except OSError as exc:
                failed.append((path, exc))
                return 0
            for name in names:
                removed += _remove(os.path.join(path, name), failed)
            os.rmdir(lp)
            return removed + 1
        if stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            # a junction or symlink: remove the LINK only - never follow it into whatever it points at
            try:
                os.rmdir(lp)
            except OSError:
                _unlink(lp)
        else:
            _unlink(lp)
        return removed + 1
    except OSError as exc:                  # in use, access denied, ...
        failed.append((path, exc))
        return removed


def delete_permanently(paths):
    """Permanently delete `paths` (files, or folders with everything in them). NOT recoverable and it skips the
    Recycle Bin. Links are removed, never followed. Returns (items_removed, [(path, error), ...])."""
    failed, removed = [], 0
    for path in paths:
        removed += _remove(path, failed)
    return removed, failed


def targets_for(path, is_dir):
    """What actually gets moved: a file itself, or the *contents* of a folder (the folder stays, so programs
    that expect e.g. their Temp or Cache folder to exist keep working)."""
    if not is_dir:
        return [path]
    try:
        return [os.path.join(path, name) for name in os.listdir(path)]
    except OSError:
        return []


# A safety net that does not depend on the folder rules: a folder holding any of these is never offered for cleaning,
# even if its name looks like a cache (embedded browsers inside launchers keep their logins in cache-like folders).
SENSITIVE_NAMES = frozenset((
    'login data', 'login data for account', 'login data-journal', 'cookies', 'cookies-journal', 'cookies.sqlite',
    'cookies.sqlite-wal', 'web data', 'web data-journal', 'logins.json', 'logins-backup.json', 'key3.db', 'key4.db',
    'signons.sqlite', 'places.sqlite', 'places.sqlite-wal', 'formhistory.sqlite', 'cert9.db', 'bookmarks', 'bookmarks.bak'))
SENSITIVE_PREFIXES = ('id_rsa', 'id_ed25519', 'id_ecdsa')       # SSH private keys (and their .pub files)
SENSITIVE_SUFFIXES = ('.kdbx', '.kdb')                           # KeePass databases


def is_sensitive_name(name):
    """Exact file names only: an npm package folder called "cookies" or a script "cookies.js" must not trigger it."""
    n = name.lower()
    return n in SENSITIVE_NAMES or n.startswith(SENSITIVE_PREFIXES) or n.endswith(SENSITIVE_SUFFIXES)


def find_sensitive(path, limit=1_000_000):
    """Path of the first saved-login / cookie / bookmark / key file inside `path`, or None.
    Looks at up to `limit` entries; links are not followed."""
    seen = 0
    stack = [path]
    while stack:
        folder = stack.pop()
        try:
            with os.scandir(long_path(folder)) as it:
                for entry in it:
                    seen += 1
                    if seen > limit:
                        return None
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if not is_link(entry.stat(follow_symlinks=False)):
                                stack.append(entry.path)
                        elif is_sensitive_name(entry.name):          # files only - a *folder* named "cookies" is harmless
                            return entry.path
                    except OSError:
                        pass
        except OSError:
            continue
    return None


def open_recycle_bin():
    os.startfile('shell:RecycleBinFolder')
