"""Move things to the Recycle Bin. Nothing here deletes permanently by itself: every item goes through the
Windows shell with "undo" enabled, and Windows asks first if an item is too big for the Recycle Bin."""
import ctypes
import os

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
