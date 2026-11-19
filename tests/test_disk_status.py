"""Tests for disk_status.py.  Run:  python3 -m unittest discover -s tests"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

import disk_status  # noqa: E402


def write(path, nbytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as fh:
        fh.write(b'x' * nbytes)


def expected_usage(root):
    """Reference disk usage, like du: dirs + files, hard links once."""
    seen = set()
    total = os.lstat(root).st_blocks * 512
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            st = os.lstat(os.path.join(dirpath, name))
            if st.st_nlink > 1 and not os.path.isdir(os.path.join(dirpath,
                                                                  name)):
                key = (st.st_dev, st.st_ino)
                if key in seen:
                    continue
                seen.add(key)
            total += st.st_blocks * 512
    return total


def subtree_totals(data):
    data.prepare()
    return dict((data.path_of(i), (data.tot[i], data.tfiles[i]))
                for i in range(len(data.names)))


class Opts(object):
    min_percent = 1.0
    max_depth = None
    depth = 3
    top = 5
    top_dirs = 30
    top_files = 50
    top_ext = 20
    tree = 'both'


class DiskStatusTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='disk_status_test_')
        r = cls.root = os.path.join(cls.tmp, 'root')
        write(os.path.join(r, 'big', 'inner', 'blob.bin'), 3000000)
        write(os.path.join(r, 'big', 'inner', 'small.txt'), 10)
        write(os.path.join(r, 'big', 'mid.dat'), 500000)
        for i in range(300):
            write(os.path.join(r, 'many', 'd%03d' % (i % 30),
                               'f%03d.log' % i), 1000)
        write(os.path.join(r, 'chain', 'a', 'b', 'c', 'deep.iso'), 200000)
        write(os.path.join(r, 'links', 'orig.mkv'), 700000)
        os.link(os.path.join(r, 'links', 'orig.mkv'),
                os.path.join(r, 'links', 'copy.mkv'))
        os.link(os.path.join(r, 'links', 'orig.mkv'),
                os.path.join(r, 'big', 'third.mkv'))
        os.symlink('/etc', os.path.join(r, 'links', 'to_etc'))
        os.symlink('../big', os.path.join(r, 'links', 'to_big'))
        write(os.path.join(r, 'skipme', 'huge.bin'), 900000)
        os.makedirs(os.path.join(r, 'empty'))
        bad = os.path.join(os.fsencode(r), b'odd\xffname.txt')
        with open(bad, 'wb') as fh:
            fh.write(b'y' * 100)
        write(os.path.join(r, 'wide', 'new\nline.txt'), 5)
        write(os.path.join(r, '\u4e2d\u6587', 'file.txt'), 20000)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def scan(self, **kw):
        kw.setdefault('progress', False)
        return disk_status.Scanner(self.root, **kw).run()

    def test_total_matches_du_reference(self):
        data = self.scan(jobs=1)
        data.prepare()
        self.assertEqual(data.tot[0], expected_usage(self.root))

    def test_parallel_and_split_tasks_match_serial(self):
        serial = subtree_totals(self.scan(jobs=1))
        for jobs, task_size in ((2, 20000), (4, 100), (3, 100)):
            par = subtree_totals(self.scan(jobs=jobs, task_size=task_size))
            self.assertEqual(serial, par, (jobs, task_size))

    def test_hard_link_counted_once(self):
        data = self.scan(jobs=2)
        data.prepare()
        mkv = [f for f in data.top_files if f[2].endswith('.mkv')]
        self.assertEqual(len(mkv), 1)
        self.assertEqual(mkv[0][3], 3)          # nlink

    def test_apparent_size(self):
        data = self.scan(jobs=2, apparent=True)
        data.prepare()
        expect = 0
        seen = set()
        for dirpath, dirnames, filenames in os.walk(self.root):
            for name in dirnames + filenames:
                st = os.lstat(os.path.join(dirpath, name))
                if stat.S_ISDIR(st.st_mode):
                    continue
                if (st.st_dev, st.st_ino) in seen:
                    continue
                seen.add((st.st_dev, st.st_ino))
                expect += st.st_size
        self.assertEqual(data.tot[0], expect)

    def test_exclude(self):
        data = self.scan(jobs=2, excludes=['skip*', '*.log'])
        data.prepare()
        paths = set(data.path_of(i) for i in range(len(data.names)))
        self.assertNotIn(os.path.join(self.root, 'skipme'), paths)
        self.assertNotIn('.log', data.ext)

    def test_save_load_and_subroot(self):
        data = self.scan(jobs=2)
        for name in ('s.scan', 's.scan.gz'):
            path = os.path.join(self.tmp, name)
            data.save(path)
            back = disk_status.ScanData.load(path)
            self.assertEqual(subtree_totals(data), subtree_totals(back))
        idx = back.find(os.path.join(self.root, 'big'))
        self.assertIsNotNone(idx)
        self.assertEqual(back.path_of(idx), os.path.join(self.root, 'big'))
        self.assertIsNone(back.find(os.path.join(self.root, 'nope')))
        self.assertIsNone(back.find('/'))

    def test_report_renders(self):
        data = self.scan(jobs=2)
        data.prepare()
        lines = disk_status.Report(data, 0, Opts()).render()
        text = '\n'.join(lines)
        for sec in ('[1]', '[2]', '[3]', '[4]', '[5]', '[6]'):
            self.assertIn(sec, text)
        self.assertIn('blob.bin', text)
        self.assertIn('chain/a/b/c/', text)          # merged chain
        self.assertIn('odd\\xffname.txt', text)       # escaped bad byte
        self.assertIn('new?line.txt', text)           # control char
        self.assertIn('[hard link x3]', text)
        self.assertIn('\u4e2d\u6587', text)
        text.encode('utf-8')                          # valid UTF-8 output

    def test_cli_end_to_end(self):
        out = os.path.join(self.tmp, 'report.txt')
        scan = os.path.join(self.tmp, 'cli.scan')
        script = os.path.join(REPO, 'disk_status.py')
        subprocess.check_call([sys.executable, script, self.root, '-q',
                               '-j', '2', '-x', '--save', scan, '-o', out])
        with open(out, 'rb') as fh:
            first = fh.read()
        sub = os.path.join(self.root, 'big')
        res = subprocess.run([sys.executable, script, '--load', scan, sub,
                              '-q', '--tree', 'adaptive'],
                             stdout=subprocess.PIPE, check=True)
        self.assertIn(b'Report root   : ' + sub.encode(), res.stdout)
        self.assertIn(b'Scanned path', first)
        bad = subprocess.run([sys.executable, script, '--load', scan,
                              '/definitely/not/here', '-q'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(bad.returncode, 2)

    def test_unreadable_directory_is_reported_and_skipped(self):
        blocked = os.path.join(self.root, 'big', 'inner')
        real_scandir = os.scandir

        def fake_scandir(path):
            if path == blocked:
                raise PermissionError(13, 'Permission denied', path)
            return real_scandir(path)

        disk_status.os.scandir = fake_scandir
        try:
            data = self.scan(jobs=1)
        finally:
            disk_status.os.scandir = real_scandir
        data.prepare()
        self.assertEqual(data.n_errors, 1)
        self.assertEqual(data.errors[0], (blocked, 'Permission denied'))
        idx = data.find(blocked)
        self.assertEqual(data.tfiles[idx], 0)
        text = '\n'.join(disk_status.Report(data, 0, Opts()).render())
        self.assertIn(blocked + ': Permission denied', text)

    def test_sources_are_ascii(self):
        for name in (os.path.join(REPO, 'disk_status.py'),
                     os.path.abspath(__file__)):
            with open(name, 'rb') as fh:
                raw = fh.read()
            self.assertTrue(all(b < 128 for b in raw), name)


if __name__ == '__main__':
    unittest.main()
