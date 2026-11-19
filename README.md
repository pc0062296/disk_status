# disk_status

Find which directories and files use the most disk space on Linux, so you
can clean them up by hand.

- One scan, many views: hot path, adaptive tree, fixed top-N tree,
  directories holding the biggest files, largest files, usage by extension.
- Fast: the scan is split over several worker processes (`-j`). On a
  1.2M-file test tree, 4 processes took 1.5 s, versus 2.4 s for `du -s`.
- Scan once, report many times: `--save` the scan, then `--load` it to
  re-render with other settings or for any subdirectory, without rescanning.
- Same totals as `du`: disk usage by default (`--apparent-size` for file
  sizes), hard links counted once, symlinks not followed, `-x` stays on one
  filesystem.
- Python 3.6+, standard library only, single file.

## Usage

Scan, save the result and write the report:

```bash
python3 disk_status.py /data -x --save data.scan -o report.txt
```

Render the report again from the saved scan (no rescan), with other settings
or for one subdirectory:

```bash
python3 disk_status.py --load data.scan -p 0.5 -d 4 -t 8 -o report.txt
python3 disk_status.py --load data.scan /data/projects -o projects.txt
```

On a busy server, run the scan at low priority:

```bash
nice -n 19 ionice -c3 python3 disk_status.py /data -x --save data.scan -o report.txt
```

## Report sections

| Section | What it shows |
| --- | --- |
| Summary / hot path | Totals, then the chain of biggest subdirectories from the root down |
| [1] Adaptive tree | Every directory holding >= `-p` percent of the total (default 1%), at any depth |
| [2] Fixed tree | Top `-t` subdirectories per level, `-d` levels deep (default 5 x 3) |
| [3] Directories by own files | Folders whose direct files (not subfolders) use the most space |
| [4] Largest files | Size, modification date, path; hard links are marked |
| [5] By extension | Files and bytes per file extension |
| [6] Problems | Skipped mount points (`-x`) and unreadable paths |

In the trees, `[files directly in this dir]` is the size of the files that
sit in that directory itself, and `(N smaller dirs, M files directly here)`
sums up everything below the threshold. A chain of directories that contain
no files and only one subdirectory is shown as one line, e.g. `a/b/c/`.

## Performance notes

- `-j` defaults to the number of CPUs (max 8). On SSD, RAID, or network
  storage, more processes help. On a single spinning disk with a cold cache,
  the disk is the limit; try `-j 2` to `-j 4`.
- A second scan is much faster than the first, because the kernel caches
  directory metadata.
- Memory use is small: about 80 MB for 300k directories and 600k files.
  Only the directory table and the `--keep-files` largest files (default
  10000) are kept.
- Saved scans use Python pickle. Only load scan files you created yourself.

## Tests

```bash
python3 -m unittest discover -s tests
```
