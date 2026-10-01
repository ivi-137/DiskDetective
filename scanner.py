"""Fast multi-threaded folder-size scanner (read-only)."""
import heapq
import itertools
import os
import queue
import stat
import threading
import time

FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
CLOUD_ONLY = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS

IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003   # junction
IO_REPARSE_TAG_SYMLINK = 0xA000000C
LINK_TAGS = (IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK)


def fmt_size(n):
    if n is None:
        return '—'
    value = float(n)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB', 'PB'):
        if value < 1024 or unit == 'PB':
            if unit == 'B':
                return f'{int(value)} B'
            return f'{value:.1f} {unit}' if value < 100 else f'{value:.0f} {unit}'
        value /= 1024


def long_path(p):
    """Prefix paths that are too long for the classic 260-character limit."""
    if len(p) < 240 or p.startswith('\\\\?\\'):
        return p
    if p.startswith('\\\\'):
        return '\\\\?\\UNC\\' + p[2:]
    return '\\\\?\\' + p


def is_link(st):
    return stat.S_ISLNK(st.st_mode) or getattr(st, 'st_reparse_tag', 0) in LINK_TAGS


def is_cloud_only(st):
    return bool(getattr(st, 'st_file_attributes', 0) & CLOUD_ONLY)


class Node:
    """One scanned folder. Only folders are kept in memory; files are summed."""
    __slots__ = ('name', 'parent', 'children', 'own_size', 'own_files', 'size', 'files', 'dirs', 'denied')

    def __init__(self, name, parent):
        self.name = name
        self.parent = parent
        self.children = None
        self.own_size = self.own_files = 0
        self.size = self.files = self.dirs = 0
        self.denied = False

    def path(self):
        parts = []
        node = self
        while node.parent is not None:
            parts.append(node.name)
            node = node.parent
        path = node.name
        for part in reversed(parts):
            path = os.path.join(path, part)
        return path

    def child_map(self):
        return {c.name.lower(): c for c in (self.children or ())}


class _Stats:
    __slots__ = ('files', 'dirs', 'bytes', 'errors', 'links', 'cloud_files', 'cloud_bytes', 'current')

    def __init__(self):
        self.files = self.dirs = self.bytes = self.errors = self.links = 0
        self.cloud_files = self.cloud_bytes = 0
        self.current = ''


class Scanner:
    def __init__(self, root, workers=None, top_n=500, post=None):
        root = os.path.normpath(root)
        if len(root) == 2 and root[1] == ':':
            root += '\\'
        self.root_path = root
        self.workers = workers or min(32, (os.cpu_count() or 4) * 2)
        self.top_n = top_n
        self.post = post
        self.root_node = Node(root, None)
        self.nodes = [self.root_node]       # parents always precede their children
        self.biggest = []                    # [(size, path)] largest first
        self.result = None                   # whatever `post` returned
        self.finished = False
        self.cancelled = False
        self.started = time.time()
        self.ended = None
        self._q = queue.LifoQueue()
        self._cancel = threading.Event()
        self._stats = [_Stats() for _ in range(self.workers)]
        self._heaps = [[] for _ in range(self.workers)]

    # -- control ---------------------------------------------------------
    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def cancel(self):
        self.cancelled = True
        self._cancel.set()

    def snapshot(self):
        total = dict(files=0, dirs=0, bytes=0, errors=0, links=0, cloud_files=0, cloud_bytes=0, current='')
        for s in self._stats:
            total['files'] += s.files
            total['dirs'] += s.dirs
            total['bytes'] += s.bytes
            total['errors'] += s.errors
            total['links'] += s.links
            total['cloud_files'] += s.cloud_files
            total['cloud_bytes'] += s.cloud_bytes
            if s.current:
                total['current'] = s.current
        return total

    # -- internals -------------------------------------------------------
    def _run(self):
        threads = [threading.Thread(target=self._worker, args=(i,), daemon=True) for i in range(self.workers)]
        for t in threads:
            t.start()
        self._q.put(self.root_node)
        self._q.join()
        for _ in threads:
            self._q.put(None)
        for t in threads:
            t.join()
        try:
            self._aggregate()
            self.biggest = heapq.nlargest(self.top_n, itertools.chain.from_iterable(self._heaps))
            if self.post:
                self.result = self.post(self)
        finally:
            self.ended = time.time()
            self.finished = True

    def _worker(self, index):
        stats, heap = self._stats[index], self._heaps[index]
        while True:
            node = self._q.get()
            try:
                if node is None:
                    return
                if not self._cancel.is_set():
                    self._scan_dir(node, stats, heap)
            except Exception:
                stats.errors += 1
            finally:
                self._q.task_done()

    def _scan_dir(self, node, stats, heap):
        path = node.path()
        stats.current = path
        own = nfiles = 0
        children = None
        try:
            it = os.scandir(long_path(path))
        except OSError:
            node.denied = True
            stats.errors += 1
            return
        top_n = self.top_n
        with it:
            while True:
                try:
                    entry = next(it)
                except StopIteration:
                    break
                except OSError:
                    stats.errors += 1
                    break
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    stats.errors += 1
                    continue
                mode = st.st_mode
                if stat.S_ISDIR(mode):
                    if getattr(st, 'st_reparse_tag', 0) in LINK_TAGS:
                        stats.links += 1
                        continue
                    child = Node(entry.name, node)
                    if children is None:
                        children = []
                    children.append(child)
                    self.nodes.append(child)
                    self._q.put(child)
                    stats.dirs += 1
                elif stat.S_ISREG(mode):
                    nfiles += 1
                    size = st.st_size
                    if is_cloud_only(st):
                        stats.cloud_files += 1
                        stats.cloud_bytes += size
                        continue
                    own += size
                    if len(heap) < top_n:
                        heapq.heappush(heap, (size, os.path.join(path, entry.name)))
                    elif size > heap[0][0]:
                        heapq.heapreplace(heap, (size, os.path.join(path, entry.name)))
        node.children = children
        node.own_size = own
        node.own_files = nfiles
        stats.files += nfiles
        stats.bytes += own

    def _aggregate(self):
        nodes = self.nodes
        for n in nodes:
            n.size = n.own_size
            n.files = n.own_files
            n.dirs = 0
        for n in reversed(nodes):       # children come after parents, so this is bottom-up
            p = n.parent
            if p is not None:
                p.size += n.size
                p.files += n.files
                p.dirs += n.dirs + 1


def find_cleanup_candidates(scanner, classify_dir, safe_level, min_size=1 << 20):
    """Top-most folders judged safe to delete (never a folder inside another candidate)."""
    candidates = [n for n in scanner.nodes if n.size >= min_size and classify_dir(n.path()).level == safe_level]
    chosen = set(map(id, candidates))
    out = []
    for n in candidates:
        p = n.parent
        covered = False
        while p is not None:
            if id(p) in chosen:
                covered = True
                break
            p = p.parent
        if not covered:
            out.append(n)
    out.sort(key=lambda n: n.size, reverse=True)
    return out


# ---------------------------------------------------------------------------
# Updating a finished scan after something was cleaned up
# ---------------------------------------------------------------------------
def under(path, base):
    """True if `path` is `base` or inside it (case-insensitive, Windows style)."""
    p, b = os.path.normcase(os.path.normpath(path)), os.path.normcase(os.path.normpath(base)).rstrip(os.sep)
    return p == b or p.startswith(b + os.sep)


def find_node(root, path):
    """The scanned Node for `path`, or None if it was not part of the scan."""
    try:
        rel = os.path.relpath(path, root.path())
    except ValueError:
        return None
    if rel == '.':
        return root
    node = root
    for part in rel.split(os.sep):
        if part == '..':
            return None
        node = node.child_map().get(part.lower()) if node.children else None
        if node is None:
            return None
    return node


def _preorder(root):
    out, stack = [], [root]
    while stack:
        n = stack.pop()
        out.append(n)
        stack.extend(n.children or ())
    return out


def rescan_path(scanner, path):
    """Re-measure one folder of a finished scan (blocking) and fix every total above it."""
    node = find_node(scanner.root_node, path)
    if node is None:
        return False
    full = node.path()
    parent = node.parent
    if not os.path.isdir(long_path(full)) and parent is not None:     # the folder itself is gone
        parent.children = [c for c in (parent.children or ()) if c is not node]
        d_size, d_files, d_dirs = -node.size, -node.files, -(node.dirs + 1)
    else:
        sub = Scanner(full, workers=min(8, scanner.workers), top_n=scanner.top_n)
        sub.start()
        while not sub.finished:
            time.sleep(0.05)
        new = sub.root_node
        d_size, d_files, d_dirs = new.size - node.size, new.files - node.files, new.dirs - node.dirs
        node.children = new.children
        for c in node.children or ():
            c.parent = node
        node.own_size, node.own_files = new.own_size, new.own_files
        node.size, node.files, node.dirs, node.denied = new.size, new.files, new.dirs, new.denied
        kept = [e for e in scanner.biggest if not under(e[1], full)]
        scanner.biggest = heapq.nlargest(scanner.top_n, kept + sub.biggest)
    p = parent
    while p is not None:
        p.size += d_size
        p.files += d_files
        p.dirs += d_dirs
        p = p.parent
    if parent is not None and not os.path.isdir(long_path(full)):
        scanner.biggest = [e for e in scanner.biggest if not under(e[1], full)]
    scanner.nodes = _preorder(scanner.root_node)
    return True
