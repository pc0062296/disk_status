#!/usr/bin/env python3
"""
disk_status.py - find which directories and files use the most disk space.

The tree is scanned once (optionally with several worker processes) and a
plain-text report is printed:

  [0] summary and the "hot path" (follow the biggest subdirectory down)
  [1] adaptive tree : expand every directory holding >= P% of the total
  [2] fixed tree    : top N subdirectories per level, down to depth D
  [3] directories whose own (direct) files use the most space
  [4] largest files
  [5] usage by file extension
  [6] skipped mount points and errors

The scan result can be saved (--save) and rendered again later (--load)
without rescanning, optionally rooted at any subdirectory (--root).

Requirements: Linux, Python 3.6+, standard library only.

Examples:
  python3 disk_status.py /data -x --save data.scan -o report.txt
  python3 disk_status.py --load data.scan -o report.txt
  python3 disk_status.py --load data.scan /data/projects -p 0.5 -o proj.txt
"""

import argparse
import bisect
import gc
import gzip
import heapq
import multiprocessing
import os
import pickle
import queue
import re
import signal
import sys
import time
from array import array
from fnmatch import translate as fnmatch_translate

FORMAT_TAG = 'disk_status-scan'
FORMAT_VERSION = 1

S_IFMT = 0o170000
S_IFDIR = 0o040000

MAX_ERRORS_KEPT = 500
MAX_MOUNTS_KEPT = 200
MAX_ERRORS_PER_TASK = 100

# Control characters in file names would break the report layout.
_CTRL_TABLE = dict((i, '?') for i in list(range(32)) + [127])


# ---------------------------------------------------------------------------
# Worker side: scan a bounded piece of the tree
# ---------------------------------------------------------------------------
#
# A task is a list of directories to scan.  The worker walks them depth
# first, but stops after `budget` directory entries and hands the rest of
# its stack back to the dispatcher, which redistributes the work.  This
# keeps every process busy even when one subtree is much larger than the
# others.
#
# Directory references in a result use one integer:
#   ref >= 0  -> global directory index (already known to the dispatcher)
#   ref <  0  -> local index (-1 - ref) into this result's new directories
#
# Files with more than one hard link are not counted by the worker; they
# are sent back so the dispatcher can count each inode exactly once.

_CFG = None


def _set_config(cfg):
    global _CFG
    _CFG = cfg


def _init_worker(cfg):
    _set_config(cfg)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    gc.disable()


def _err_text(exc):
    return exc.strerror or exc.__class__.__name__


def scan_task(task):
    roots, threshold = task
    root_dev, one_fs, apparent, excl_pat, budget, keep = _CFG
    excl = re.compile(excl_pat).match if excl_pat else None

    scandir = os.scandir
    heappush = heapq.heappush
    heapreplace = heapq.heapreplace

    names = []        # new directories scanned in this task
    parents = []
    selfb = []
    counts = []
    updates = []      # (global_idx, bytes, files) for task roots
    pend = []         # (parent_ref, name, path, own_bytes) found, not scanned
    requeue = []      # (global_idx, path) task roots not scanned
    hard = []         # (dev, ino, size, dir_ref, mtime, path, st_size, nlink)
    top = []          # heap of (size, mtime, path, nlink)
    ext = {}          # ext -> [files, bytes]
    errors = []
    mounts = []
    n_err = 0
    n_files = 0
    n_bytes = 0
    a_bytes = 0
    done = 0

    stack = [(0, None, path, 0, g) for g, path in reversed(roots)]

    while stack:
        if done >= budget:
            for pref, name, path, own, g in stack:
                if g >= 0:
                    requeue.append((g, path))
                else:
                    pend.append((pref, name, path, own))
            break

        pref, dname, path, own, g = stack.pop()
        if g >= 0:
            ref = g
            li = -1
        else:
            li = len(names)
            names.append(dname)
            parents.append(pref)
            selfb.append(own)
            counts.append(0)
            ref = -1 - li

        prefix = path + '/' if path != '/' else '/'
        b = 0
        c = 0
        try:
            with scandir(path) as it:
                for entry in it:
                    done += 1
                    name = entry.name
                    if excl is not None and excl(name):
                        continue
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue          # removed while we were scanning
                    except OSError as e:
                        n_err += 1
                        if len(errors) < MAX_ERRORS_PER_TASK:
                            errors.append((prefix + name, _err_text(e)))
                        continue

                    if st.st_mode & S_IFMT == S_IFDIR:
                        if one_fs and st.st_dev != root_dev:
                            mounts.append(prefix + name)
                            continue
                        # Like du: a directory's own blocks count for
                        # disk usage, but not for the apparent size.
                        stack.append((ref, name, prefix + name,
                                      0 if apparent
                                      else st.st_blocks * 512, -1))
                        continue

                    size = st.st_size if apparent else st.st_blocks * 512
                    if st.st_nlink > 1:
                        hard.append((st.st_dev, st.st_ino, size, ref,
                                     st.st_mtime, prefix + name, st.st_size,
                                     st.st_nlink))
                        continue

                    b += size
                    c += 1
                    a_bytes += st.st_size

                    d = name.rfind('.')
                    if 0 < d < len(name) - 1 and len(name) - d <= 11:
                        e = name[d:].lower()
                    else:
                        e = ''
                    s = ext.get(e)
                    if s is None:
                        ext[e] = [1, size]
                    else:
                        s[0] += 1
                        s[1] += size

                    if size > threshold:
                        if len(top) < keep:
                            heappush(top, (size, st.st_mtime, prefix + name, 1))
                        elif size > top[0][0]:
                            heapreplace(top,
                                        (size, st.st_mtime, prefix + name, 1))
        except OSError as e:
            n_err += 1
            if len(errors) < MAX_ERRORS_PER_TASK:
                errors.append((path, _err_text(e)))

        if li >= 0:
            selfb[li] += b
            counts[li] = c
        else:
            updates.append((g, b, c))
        n_files += c
        n_bytes += b

    return (names, parents, selfb, counts, updates, pend, requeue, hard,
            top, ext, errors, n_err, mounts, n_files, n_bytes, a_bytes)


# ---------------------------------------------------------------------------
# Dispatcher: owns the directory table and merges worker results
# ---------------------------------------------------------------------------

class Scanner(object):

    def __init__(self, root, jobs=1, one_fs=False, apparent=False,
                 excludes=(), keep_files=10000, task_size=20000,
                 progress=True):
        self.root = root
        self.jobs = max(1, jobs)
        self.one_fs = one_fs
        self.apparent = apparent
        self.excludes = list(excludes)
        self.keep = max(1, keep_files)
        self.task_size = max(100, task_size)
        self.progress = progress

        self.names = []
        self.parents = array('q')
        self.selfb = array('q')
        self.cnt = array('q')
        self.top = []
        self.ext = {}
        self.errors = []
        self.n_errors = 0
        self.mounts = []
        self.n_mounts = 0
        self.seen_inodes = set()
        self.pending = []
        self.files_done = 0
        self.bytes_done = 0
        self.apparent_bytes = 0

        self._t0 = 0.0
        self._last_progress = 0.0
        self._progress_len = 0
        self._tty = sys.stderr.isatty()

    def _config(self, root_dev):
        pat = None
        if self.excludes:
            pat = '|'.join('(?:%s)' % fnmatch_translate(p)
                           for p in self.excludes)
        return (root_dev, self.one_fs, self.apparent, pat,
                self.task_size, self.keep)

    def _threshold(self):
        if len(self.top) >= self.keep:
            return self.top[0][0]
        return -1

    def _next_task(self):
        pending = self.pending
        k = max(1, min(256, len(pending) // (self.jobs * 2)))
        chunk = pending[-k:]
        del pending[-k:]
        return (chunk, self._threshold())

    def _add_top(self, item):
        top = self.top
        if len(top) < self.keep:
            heapq.heappush(top, item)
        elif item[0] > top[0][0]:
            heapq.heapreplace(top, item)

    def _merge(self, res):
        (names, parents, selfb, counts, updates, pend, requeue, hard,
         top, ext, errors, n_err, mounts, n_files, n_bytes, a_bytes) = res

        base = len(self.names)
        g_parents = self.parents
        g_selfb = self.selfb
        g_cnt = self.cnt

        self.names.extend(names)
        g_parents.extend([p if p >= 0 else base - 1 - p for p in parents])
        g_selfb.extend(selfb)
        g_cnt.extend(counts)

        for g, b, c in updates:
            g_selfb[g] += b
            g_cnt[g] += c

        for pref, name, path, own in pend:
            idx = len(self.names)
            self.names.append(name)
            g_parents.append(pref if pref >= 0 else base - 1 - pref)
            g_selfb.append(own)
            g_cnt.append(0)
            self.pending.append((idx, path))
        self.pending.extend(requeue)

        g_ext = self.ext
        for e, (c, b) in ext.items():
            s = g_ext.get(e)
            if s is None:
                g_ext[e] = [c, b]
            else:
                s[0] += c
                s[1] += b

        if hard:
            seen = self.seen_inodes
            for dev, ino, size, dref, mtime, path, st_size, nlink in hard:
                key = (dev, ino)
                if key in seen:
                    continue
                seen.add(key)
                d = dref if dref >= 0 else base - 1 - dref
                g_selfb[d] += size
                g_cnt[d] += 1
                n_files += 1
                n_bytes += size
                a_bytes += st_size
                name = path[path.rfind('/') + 1:]
                dot = name.rfind('.')
                if 0 < dot < len(name) - 1 and len(name) - dot <= 11:
                    e = name[dot:].lower()
                else:
                    e = ''
                s = g_ext.get(e)
                if s is None:
                    g_ext[e] = [1, size]
                else:
                    s[0] += 1
                    s[1] += size
                self._add_top((size, mtime, path, nlink))

        for item in top:
            self._add_top(item)

        self.n_errors += n_err
        room = MAX_ERRORS_KEPT - len(self.errors)
        if room > 0:
            self.errors.extend(errors[:room])
        self.n_mounts += len(mounts)
        room = MAX_MOUNTS_KEPT - len(self.mounts)
        if room > 0:
            self.mounts.extend(mounts[:room])

        self.files_done += n_files
        self.bytes_done += n_bytes
        self.apparent_bytes += a_bytes

    def _show_progress(self, final=False):
        if not self.progress:
            return
        now = time.monotonic()
        interval = 0.5 if self._tty else 30.0
        if not final and now - self._last_progress < interval:
            return
        self._last_progress = now
        line = '[scan] %s files  %s dirs  %s  queue %s  %.0fs' % (
            '{:,}'.format(self.files_done), '{:,}'.format(len(self.names)),
            human(self.bytes_done), '{:,}'.format(len(self.pending)),
            now - self._t0)
        if self._tty:
            pad = max(0, self._progress_len - len(line))
            sys.stderr.write('\r' + line + ' ' * pad)
            self._progress_len = len(line)
            if final:
                sys.stderr.write('\n')
        else:
            sys.stderr.write(line + '\n')
        sys.stderr.flush()

    def run(self):
        root = self.root
        st = os.stat(root)
        if st.st_mode & S_IFMT != S_IFDIR:
            raise NotADirectoryError(root)
        self.names.append(root)
        self.parents.append(-1)
        self.selfb.append(0 if self.apparent else st.st_blocks * 512)
        self.cnt.append(0)
        self.pending.append((0, root))

        cfg = self._config(st.st_dev)
        started = time.time()
        self._t0 = time.monotonic()
        self._last_progress = self._t0
        gc_was_enabled = gc.isenabled()
        gc.disable()
        try:
            if self.jobs <= 1:
                self._run_serial(cfg)
            else:
                self._run_parallel(cfg)
        finally:
            if gc_was_enabled:
                gc.enable()
        elapsed = time.monotonic() - self._t0
        self._show_progress(final=True)

        self.top.sort(reverse=True)
        return ScanData(
            root=root, started=started, elapsed=elapsed, jobs=self.jobs,
            apparent=self.apparent, one_fs=self.one_fs,
            excludes=self.excludes, names=self.names, parents=self.parents,
            selfb=self.selfb, cnt=self.cnt, top_files=self.top,
            ext=self.ext, errors=self.errors, n_errors=self.n_errors,
            mounts=self.mounts, n_mounts=self.n_mounts,
            apparent_bytes=self.apparent_bytes)

    def _run_serial(self, cfg):
        _set_config(cfg)
        while self.pending:
            self._merge(scan_task(self._next_task()))
            self._show_progress()

    def _run_parallel(self, cfg):
        ctx = multiprocessing.get_context('fork')
        pool = ctx.Pool(self.jobs, _init_worker, (cfg,))
        results = queue.Queue()
        inflight = 0
        try:
            while self.pending or inflight:
                while self.pending and inflight < self.jobs * 2:
                    pool.apply_async(scan_task, (self._next_task(),),
                                     callback=results.put,
                                     error_callback=results.put)
                    inflight += 1
                try:
                    res = results.get(timeout=0.5)
                except queue.Empty:
                    self._show_progress()
                    continue
                inflight -= 1
                if isinstance(res, BaseException):
                    raise RuntimeError('worker process failed: %r' % (res,))
                self._merge(res)
                self._show_progress()
            pool.close()
            pool.join()
        except BaseException:
            pool.terminate()
            pool.join()
            raise


# ---------------------------------------------------------------------------
# Scan data: save / load / derived indexes
# ---------------------------------------------------------------------------

class ScanData(object):

    FIELDS = ('root', 'started', 'elapsed', 'jobs', 'apparent', 'one_fs',
              'excludes', 'names', 'parents', 'selfb', 'cnt', 'top_files',
              'ext', 'errors', 'n_errors', 'mounts', 'n_mounts',
              'apparent_bytes')

    def __init__(self, **kw):
        for f in self.FIELDS:
            setattr(self, f, kw[f])
        self.tot = None

    def save(self, path):
        payload = dict((f, getattr(self, f)) for f in self.FIELDS)
        payload['format'] = FORMAT_TAG
        payload['version'] = FORMAT_VERSION
        tmp = path + '.tmp'
        opener = gzip.open if path.endswith('.gz') else open
        with opener(tmp, 'wb') as fh:
            pickle.dump(payload, fh, protocol=4)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path):
        # Note: pickle must only be used on files you created yourself.
        with open(path, 'rb') as fh:
            magic = fh.read(2)
        opener = gzip.open if magic == b'\x1f\x8b' else open
        with opener(path, 'rb') as fh:
            payload = pickle.load(fh)
        if (not isinstance(payload, dict)
                or payload.get('format') != FORMAT_TAG):
            raise ValueError('%s is not a disk_status scan file' % path)
        if payload.get('version') != FORMAT_VERSION:
            raise ValueError('%s: unsupported scan file version %r'
                             % (path, payload.get('version')))
        return cls(**dict((f, payload[f]) for f in cls.FIELDS))

    def prepare(self):
        """Compute subtree totals and a parent -> children index."""
        if self.tot is not None:
            return
        n = len(self.names)
        parents = self.parents
        tot = array('q', self.selfb)
        tfiles = array('q', self.cnt)
        tdirs = array('q', [1]) * n
        for i in range(n - 1, 0, -1):
            p = parents[i]
            tot[p] += tot[i]
            tfiles[p] += tfiles[i]
            tdirs[p] += tdirs[i]
        self.tot = tot
        self.tfiles = tfiles
        self.tdirs = tdirs
        # Children index: node ids sorted by parent; parent < child always.
        self._order = sorted(range(1, n), key=parents.__getitem__)
        self._sorted_parents = [parents[i] for i in self._order]

    def children(self, i):
        sp = self._sorted_parents
        lo = bisect.bisect_left(sp, i)
        hi = bisect.bisect_right(sp, i, lo)
        return self._order[lo:hi]

    def path_of(self, i):
        parts = []
        names = self.names
        parents = self.parents
        while i > 0:
            parts.append(names[i])
            i = parents[i]
        if not parts:
            return self.root
        parts.reverse()
        return self.root.rstrip('/') + '/' + '/'.join(parts)

    def find(self, path):
        """Return the directory index of `path`, or None."""
        root = self.root
        path = os.path.normpath(os.path.abspath(path))
        if path == root:
            return 0
        base = root.rstrip('/') + '/'
        if not path.startswith(base):
            return None
        i = 0
        for part in path[len(base):].split('/'):
            for k in self.children(i):
                if self.names[k] == part:
                    i = k
                    break
            else:
                return None
        return i


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def human(n):
    n = float(n)
    for unit in ('B', 'K', 'M', 'G', 'T', 'P'):
        if n < 1024.0 or unit == 'P':
            if unit == 'B':
                return '%dB' % n
            return '%.1f%s' % (n, unit)
        n /= 1024.0


def clean(text):
    text = text.translate(_CTRL_TABLE)
    try:
        text.encode('utf-8')
    except UnicodeEncodeError:
        # Non-UTF-8 bytes in a file name: show them as \xNN
        text = text.encode('utf-8', 'surrogateescape').decode(
            'utf-8', 'backslashreplace')
    return text


def fmt_int(n):
    return '{:,}'.format(n)


def fmt_date(ts):
    try:
        return time.strftime('%Y-%m-%d', time.localtime(ts))
    except (OverflowError, OSError, ValueError):
        return '????-??-??'


class Report(object):

    def __init__(self, data, root_idx, opts):
        self.d = data
        self.r = root_idx
        self.o = opts
        data.prepare()
        self.total = data.tot[root_idx]
        self.root_path = data.path_of(root_idx)
        self.thr = self.total * opts.min_percent / 100.0
        self.lines = []

    # -- helpers ----------------------------------------------------------

    def pct(self, x):
        if self.total <= 0:
            return '   -  '
        return '%5.1f%%' % (100.0 * x / self.total)

    def bar(self, x, width=10):
        k = 0
        if self.total > 0:
            k = int(round(width * float(x) / self.total))
            k = min(width, max(0, k))
        return '[' + '#' * k + ' ' * (width - k) + ']'

    def row(self, size, files, label):
        return '%8s %6s %11s %s %s' % (human(size), self.pct(size),
                                       fmt_int(files), self.bar(size),
                                       clean(label))

    def header_row(self):
        return '%8s %6s %11s %-12s %s' % ('SIZE', '%ROOT', 'FILES', 'USAGE',
                                          'PATH')

    def section(self, title, note=None):
        out = self.lines
        out.append('')
        out.append('=' * 78)
        out.append(title)
        if note:
            out.append(note)
        out.append('=' * 78)

    # -- sections ---------------------------------------------------------

    def summary(self):
        d = self.d
        o = self.o
        out = self.lines
        out.append('disk_status report')
        out.append('=' * 78)
        out.append('Scanned path  : %s' % clean(d.root))
        if self.r != 0:
            out.append('Report root   : %s' % clean(self.root_path))
        out.append('Scan started  : %s' % time.strftime(
            '%Y-%m-%d %H:%M:%S', time.localtime(d.started)))
        out.append('Scan time     : %.1f s with %d process(es)'
                   % (d.elapsed, d.jobs))
        if d.apparent:
            out.append('Size metric   : apparent size (st_size)')
        else:
            out.append('Size metric   : disk usage (allocated blocks, '
                       'like du)')
        opts = ['hard links counted once', 'symlinks not followed']
        if d.one_fs:
            opts.append('one filesystem only (-x)')
        if d.excludes:
            opts.append('exclude: ' + ' '.join(d.excludes))
        out.append('Options       : %s' % clean(', '.join(opts)))
        out.append('Total size    : %s  (%s bytes)'
                   % (human(self.total), fmt_int(self.total)))
        if not d.apparent and self.r == 0:
            out.append('Apparent size : %s  (sum of file sizes)'
                       % human(d.apparent_bytes))
        out.append('Files / dirs  : %s files, %s directories'
                   % (fmt_int(d.tfiles[self.r]), fmt_int(d.tdirs[self.r])))
        out.append('Errors        : %s%s' % (
            fmt_int(d.n_errors), '  (see section [6])' if d.n_errors else ''))
        out.append('Report params : -p %g  -d %d  -t %d'
                   % (o.min_percent, o.depth, o.top))

        # Hot path
        out.append('')
        out.append('Hot path (follow the biggest subdirectory while it holds '
                   '>= %g%% of the total):' % o.min_percent)
        tot = d.tot
        selfb = d.selfb
        i = self.r
        out.append('  %8s %6s  %s' % (human(tot[i]), self.pct(tot[i]),
                                      clean(self.root_path)))
        while True:
            kids = d.children(i)
            if not kids:
                why = 'no subdirectories'
                break
            k = max(kids, key=tot.__getitem__)
            if selfb[i] > tot[k] and selfb[i] >= self.thr:
                why = ('the biggest part is the files directly in this '
                       'directory (%s in %s files)'
                       % (human(selfb[i]), fmt_int(d.cnt[i])))
                break
            if tot[k] < self.thr:
                why = ('no single subdirectory holds >= %g%%; the space is '
                       'spread over %s subdirectories'
                       % (o.min_percent, fmt_int(len(kids))))
                break
            i = k
            out.append('  %8s %6s  %s' % (human(tot[i]), self.pct(tot[i]),
                                          clean(d.path_of(i))))
        out.append('  -> stops here: %s' % why)

    def _items(self, i, depth, mode):
        """Child lines of directory i: [(kind, size, files, node, label)]."""
        d = self.d
        o = self.o
        tot = d.tot
        kids = sorted(d.children(i), key=tot.__getitem__, reverse=True)
        if mode == 'adaptive':
            if o.max_depth is not None and depth >= o.max_depth:
                return None
            n_show = 0
            for k in kids:
                if tot[k] < self.thr:
                    break
                n_show += 1
            show_self = d.cnt[i] > 0 and d.selfb[i] >= self.thr
            rest_word = 'smaller'
        else:
            if depth >= o.depth:
                return None
            n_show = min(o.top, len(kids))
            show_self = d.cnt[i] > 0
            rest_word = 'more'
        if n_show == 0 and not show_self:
            return None

        items = []
        for k in kids[:n_show]:
            # Merge a chain of directories that hold no files and exactly
            # one subdirectory into one line: a/b/c/
            label = d.names[k] + '/'
            size = tot[k]
            files = d.tfiles[k]
            while d.cnt[k] == 0:
                sub = d.children(k)
                if len(sub) != 1:
                    break
                k = sub[0]
                label += d.names[k] + '/'
            items.append(('dir', size, files, k, label))
        if show_self:
            items.append(('files', d.selfb[i], d.cnt[i], i,
                          '[files directly in this dir]'))
        items.sort(key=lambda it: it[1], reverse=True)

        hidden = kids[n_show:]
        rest_bytes = sum(tot[k] for k in hidden)
        rest_files = sum(d.tfiles[k] for k in hidden)
        parts = []
        if hidden:
            parts.append('%s %s dir%s' % (fmt_int(len(hidden)), rest_word,
                                          '' if len(hidden) == 1 else 's'))
        if not show_self:
            rest_bytes += d.selfb[i]
            if d.cnt[i] > 0:
                rest_files += d.cnt[i]
                parts.append('%s file%s directly here'
                             % (fmt_int(d.cnt[i]),
                                '' if d.cnt[i] == 1 else 's'))
        if parts:
            items.append(('rest', rest_bytes, rest_files, i,
                          '(' + ', '.join(parts) + ')'))
        if len(items) == 1 and items[0][0] == 'files':
            return None     # only its own files: nothing new to show
        return items

    def tree(self, mode):
        d = self.d
        o = self.o
        if mode == 'adaptive':
            self.section(
                '[1] Adaptive tree: every directory holding >= %g%% of the '
                'total is expanded' % o.min_percent,
                '    Big branches are followed as deep as they go; small ones '
                'are folded into (...) lines.')
        else:
            self.section(
                '[2] Fixed tree: top %d subdirectories per level, %d levels '
                'deep' % (o.top, o.depth),
                '    Siblings are sorted by size; the rest is folded into '
                '(...) lines.')
        out = self.lines
        out.append(self.header_row())
        r = self.r
        out.append(self.row(d.tot[r], d.tfiles[r], self.root_path))
        first = self._items(r, 0, mode)
        if not first:
            return
        stack = [[first, 0, '', 0]]
        while stack:
            frame = stack[-1]
            items, pos, prefix, depth = frame
            if pos >= len(items):
                stack.pop()
                continue
            frame[1] = pos + 1
            last = pos == len(items) - 1
            kind, size, files, node, label = items[pos]
            out.append(self.row(size, files,
                                prefix + ('`-- ' if last else '+-- ') + label))
            if kind == 'dir':
                sub = self._items(node, depth + 1, mode)
                if sub:
                    stack.append([sub, 0, prefix + ('    ' if last else '|   '),
                                  depth + 1])

    def top_dirs(self):
        d = self.d
        o = self.o
        self.section(
            '[3] Directories whose own files (not subdirectories) use the '
            'most space',
            '    These are the folders where the big files actually sit.')
        out = self.lines
        out.append('%8s %6s %11s  %s' % ('SIZE', '%ROOT', 'FILES', 'PATH'))
        n = len(d.names)
        r = self.r
        if r == 0:
            candidates = range(n)
        else:
            inside = bytearray(n)
            inside[r] = 1
            parents = d.parents
            for i in range(r + 1, n):
                if inside[parents[i]]:
                    inside[i] = 1
            candidates = [i for i in range(r, n) if inside[i]]
        best = heapq.nlargest(o.top_dirs, candidates,
                              key=d.selfb.__getitem__)
        for i in best:
            if d.cnt[i] == 0:
                continue
            out.append('%8s %6s %11s  %s' % (human(d.selfb[i]),
                                             self.pct(d.selfb[i]),
                                             fmt_int(d.cnt[i]),
                                             clean(d.path_of(i))))

    def top_files(self):
        d = self.d
        o = self.o
        note = None
        files = d.top_files
        if self.r != 0:
            base = self.root_path.rstrip('/') + '/'
            files = [f for f in files if f[2].startswith(base)]
            note = ('    Taken from the %s largest files recorded during the '
                    'scan (--keep-files).' % fmt_int(len(d.top_files)))
        self.section('[4] Largest files', note)
        out = self.lines
        out.append('%8s %6s  %-10s  %s' % ('SIZE', '%ROOT', 'MODIFIED',
                                          'PATH'))
        files = [f for f in files if f[0] > 0]
        if not files and self.r != 0:
            out.append('(none of the recorded files are in this directory; '
                       'scan it directly for a full list)')
        n_hard = 0
        for size, mtime, path, nlink in files[:o.top_files]:
            mark = ''
            if nlink > 1:
                mark = '  [hard link x%d]' % nlink
                n_hard += 1
            out.append('%8s %6s  %s  %s%s' % (
                human(size), self.pct(size), fmt_date(mtime), clean(path),
                mark))
        if n_hard:
            out.append('')
            out.append('[hard link xN]: the same data has N names; deleting '
                       'one name frees nothing')
            out.append('until all N names are deleted. Its size is counted '
                       'once, in the first')
            out.append('directory where the scan met it.')

    def extensions(self):
        d = self.d
        o = self.o
        note = None
        if self.r != 0:
            note = '    Note: this section covers the whole scan, not only ' \
                   'the report root.'
        self.section('[5] Usage by file extension', note)
        out = self.lines
        out.append('%-12s %12s %8s %6s' % ('EXTENSION', 'FILES', 'SIZE',
                                           '%ALL'))
        total = sum(b for c, b in d.ext.values()) or 1
        rows = sorted(d.ext.items(), key=lambda kv: kv[1][1], reverse=True)
        for e, (c, b) in rows[:o.top_ext]:
            out.append('%-12s %12s %8s %5.1f%%' % (
                clean(e) if e else '(none)', fmt_int(c), human(b),
                100.0 * b / total))

    def problems(self):
        d = self.d
        self.section('[6] Skipped mount points and errors')
        out = self.lines
        if d.n_mounts:
            out.append('Skipped %s directories on other filesystems (-x):'
                       % fmt_int(d.n_mounts))
            for m in d.mounts:
                out.append('  ' + clean(m))
            if d.n_mounts > len(d.mounts):
                out.append('  ... (%s more)'
                           % fmt_int(d.n_mounts - len(d.mounts)))
        if d.n_errors:
            out.append('%s errors (unreadable files/directories were '
                       'skipped):' % fmt_int(d.n_errors))
            for path, msg in d.errors:
                out.append('  %s: %s' % (clean(path), clean(msg)))
            if d.n_errors > len(d.errors):
                out.append('  ... (%s more)'
                           % fmt_int(d.n_errors - len(d.errors)))
        if not d.n_mounts and not d.n_errors:
            out.append('None.')

    def render(self):
        o = self.o
        self.summary()
        if o.tree in ('both', 'adaptive'):
            self.tree('adaptive')
        if o.tree in ('both', 'fixed'):
            self.tree('fixed')
        if o.top_dirs > 0:
            self.top_dirs()
        if o.top_files > 0:
            self.top_files()
        if o.top_ext > 0:
            self.extensions()
        self.problems()
        self.lines.append('')
        return self.lines


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def default_jobs():
    try:
        n = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        n = os.cpu_count() or 1
    return max(1, min(8, n))


def build_parser():
    p = argparse.ArgumentParser(
        prog='disk_status.py',
        description='Find which directories and files use the most disk '
                    'space.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='examples:\n'
               '  %(prog)s /data -x --save data.scan -o report.txt\n'
               '  %(prog)s --load data.scan -o report.txt\n'
               '  %(prog)s --load data.scan /data/projects -p 0.5\n')
    p.add_argument('path', nargs='?',
                   help='directory to scan; with --load: directory to use '
                        'as the report root (default: the scanned path)')

    g = p.add_argument_group('scanning')
    g.add_argument('-j', '--jobs', type=int, default=default_jobs(),
                   help='worker processes (default: %(default)s; '
                        '1 = no multiprocessing)')
    g.add_argument('-x', '--one-file-system', action='store_true',
                   help='do not descend into other mounted filesystems')
    g.add_argument('--apparent-size', action='store_true',
                   help='use file sizes (st_size) instead of disk usage')
    g.add_argument('--exclude', action='append', default=[],
                   metavar='PATTERN',
                   help='skip files/directories whose name matches this '
                        'shell pattern (repeatable), e.g. --exclude .snapshot')
    g.add_argument('--keep-files', type=int, default=10000, metavar='N',
                   help='how many of the largest files to remember '
                        '(default: %(default)s)')
    g.add_argument('--task-size', type=int, default=20000, metavar='N',
                   help=argparse.SUPPRESS)
    g.add_argument('--save', metavar='FILE',
                   help='save the scan result to FILE (add .gz to compress)')
    g.add_argument('--load', metavar='FILE',
                   help='do not scan; render the report from a saved FILE')
    g.add_argument('-q', '--quiet', action='store_true',
                   help='no progress output on stderr')

    g = p.add_argument_group('report')
    g.add_argument('--root', metavar='DIR',
                   help='render the report for this subdirectory only')
    g.add_argument('-o', '--output', metavar='FILE',
                   help='write the report to FILE instead of stdout')
    g.add_argument('--tree', choices=('both', 'adaptive', 'fixed', 'none'),
                   default='both', help='which tree views to print '
                                        '(default: %(default)s)')
    g.add_argument('-p', '--min-percent', type=float, default=1.0,
                   metavar='P',
                   help='adaptive tree / hot path: expand directories '
                        'holding >= P%% of the total (default: %(default)s)')
    g.add_argument('--max-depth', type=int, default=None, metavar='N',
                   help='adaptive tree: stop after N levels '
                        '(default: unlimited)')
    g.add_argument('-d', '--depth', type=int, default=3, metavar='N',
                   help='fixed tree: levels to show (default: %(default)s)')
    g.add_argument('-t', '--top', type=int, default=5, metavar='N',
                   help='fixed tree: subdirectories per level '
                        '(default: %(default)s)')
    g.add_argument('--top-dirs', type=int, default=30, metavar='N',
                   help='rows in section [3] (default: %(default)s)')
    g.add_argument('-f', '--top-files', type=int, default=50, metavar='N',
                   help='rows in section [4] (default: %(default)s)')
    g.add_argument('--top-ext', type=int, default=20, metavar='N',
                   help='rows in section [5] (default: %(default)s)')
    return p


def write_output(lines, path):
    data = '\n'.join(lines).encode('utf-8', 'surrogateescape')
    if path:
        with open(path, 'wb') as fh:
            fh.write(data)
    else:
        sys.stdout.flush()
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


def main(argv=None):
    parser = build_parser()
    a = parser.parse_args(argv)

    if a.min_percent < 0 or a.depth < 0 or a.top < 0:
        parser.error('-p, -d and -t must not be negative')

    try:
        if a.load:
            if a.path and a.root:
                parser.error('with --load give the report root either as '
                             'PATH or as --root, not both')
            data = ScanData.load(a.load)
            report_root = a.root or a.path
        else:
            if not a.path:
                parser.error('PATH is required unless --load is used')
            root = os.path.normpath(os.path.abspath(a.path))
            if not os.path.isdir(root):
                parser.error('not a directory: %s' % a.path)
            scanner = Scanner(root, jobs=a.jobs,
                              one_fs=a.one_file_system,
                              apparent=a.apparent_size,
                              excludes=a.exclude, keep_files=a.keep_files,
                              task_size=a.task_size, progress=not a.quiet)
            data = scanner.run()
            if a.save:
                data.save(a.save)
                if not a.quiet:
                    sys.stderr.write('[scan] saved to %s\n' % a.save)
            report_root = a.root

        if not a.quiet:
            sys.stderr.write('[report] building report ...\n')
        data.prepare()
        root_idx = 0
        if report_root:
            root_idx = data.find(report_root)
            if root_idx is None:
                sys.stderr.write('error: %s is not a directory inside the '
                                 'scan of %s\n' % (report_root, data.root))
                return 2
        lines = Report(data, root_idx, a).render()
        write_output(lines, a.output)
        if a.output and not a.quiet:
            sys.stderr.write('[report] written to %s\n' % a.output)
        return 0
    except KeyboardInterrupt:
        sys.stderr.write('\ninterrupted\n')
        return 130
    except (OSError, ValueError) as e:
        sys.stderr.write('error: %s\n' % e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
