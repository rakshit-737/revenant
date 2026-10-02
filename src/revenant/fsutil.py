"""Evidence-directory walking that never leaves the directory it was given.

Symlinks and NTFS junctions inside an evidence tree may point anywhere on the
examiner's disk (e.g. profile junctions in a mounted image). They are skipped,
never followed, and every yielded file is re-checked to resolve inside the root.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from pathlib import Path


def is_link(p: Path) -> bool:
    """True for a symlink or (on Windows) an NTFS junction / reparse point."""
    try:
        if p.is_symlink():
            return True
        is_junction = getattr(p, "is_junction", None)  # Python 3.12+
        if is_junction is not None and is_junction():
            return True
        return bool(getattr(os.lstat(p), "st_file_attributes", 0) & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
    except OSError:
        return False


def iter_files(root: str | Path, suffixes: Iterable[str] | None = None,
               skipped: list[str] | None = None) -> Iterator[Path]:
    """Yield regular files under ``root`` (sorted), skipping links and anything resolving outside it."""
    root = Path(root)
    base = root.resolve()
    sufs = tuple(s.lower() for s in suffixes) if suffixes else None
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        d = Path(dirpath)
        keep = []
        for name in dirnames:
            if is_link(d / name):
                if skipped is not None:
                    skipped.append(str(d / name))
            else:
                keep.append(name)
        dirnames[:] = keep
        for name in filenames:
            f = d / name
            if sufs and not name.lower().endswith(sufs):
                continue
            if is_link(f):
                if skipped is not None:
                    skipped.append(str(f))
                continue
            try:
                if not f.resolve(strict=True).is_relative_to(base):
                    if skipped is not None:
                        skipped.append(str(f))
                    continue
            except OSError:
                pass  # unreadable files are reported by the loaders
            out.append(f)
    yield from sorted(out)
