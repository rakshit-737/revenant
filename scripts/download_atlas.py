#!/usr/bin/env python3
"""Download the ATLAS attack-investigation dataset (Alsaheel et al., USENIX Security 2021).

Source: https://github.com/purseclab/ATLAS (Apache-2.0), pinned to commit
``e46096d1947e4f059e73a0ac2b9a9707812fd4bc``. Ten attacks: four single-host
(S1-S4) and six multi-host (M1-M6), each as

* ``raw_logs/<A>.zip`` -- the raw Windows security-audit, DNS and Firefox logs;
* ``paper_experiments/<A>.zip`` -- the authors' preprocessed logs, their
  malicious-entity labels and a copy of their code for that experiment;
* ``paper_experiments/docs/atlas.xlsx`` -- the per-attack numbers behind the paper's tables.

Every file is checked against ``data/atlas_manifest.json`` (size, git blob
SHA-1 as published by GitHub, and SHA-256). Downloads are resumable (HTTP
Range) because raw.githubusercontent.com drops long transfers on slow links.

Usage::

    python scripts/download_atlas.py [--dest DIR] [--only S1 S2 ...] [--no-extract] [--no-raw]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data" / "atlas_manifest.json"
DEFAULT_DEST = Path(os.environ.get("REVENANT_DATA", ROOT.parent.parent / "datasets" / "revenant")) / "atlas"
COMMIT = "e46096d1947e4f059e73a0ac2b9a9707812fd4bc"
RAW = f"https://raw.githubusercontent.com/purseclab/ATLAS/{COMMIT}/"


def git_blob_sha1(path: Path) -> str:
    h = hashlib.sha1(f"blob {path.stat().st_size}\0".encode(), usedforsecurity=False)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, out: Path, size: int, attempts: int = 40) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(1, attempts + 1):
        have = out.stat().st_size if out.exists() else 0
        if have == size:
            return
        if have > size:
            out.unlink()
            have = 0
        req = urllib.request.Request(url, headers={"User-Agent": "revenant-downloader", "Range": f"bytes={have}-"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp, out.open("ab" if have else "wb") as fh:  # noqa: S310  # nosec B310 - fixed https URL from the pinned manifest
                if have and resp.status != 206:  # server ignored Range: restart
                    fh.truncate(0)
                while chunk := resp.read(1 << 16):
                    fh.write(chunk)
        except (OSError, urllib.error.URLError) as exc:
            print(f"  {out.name}: {exc!r}; resuming ({attempt}/{attempts})", file=sys.stderr)
            time.sleep(min(30, 2 * attempt))
    if not out.exists() or out.stat().st_size != size:
        raise RuntimeError(f"could not download {url}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    ap.add_argument("--only", nargs="*", help="attack ids, e.g. S1 M2")
    ap.add_argument("--no-extract", action="store_true")
    ap.add_argument("--no-raw", action="store_true", help="skip raw_logs/*.zip (the experiments hold the preprocessed logs)")
    ap.add_argument("--pin", action="store_true", help="record SHA-256 for entries that have none yet")
    args = ap.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    changed = False
    for f in manifest["files"]:
        attack = Path(f["path"]).stem
        if args.only and attack not in args.only and f["path"].endswith(".zip"):
            continue
        if args.no_raw and f["path"].startswith("raw_logs/"):
            continue
        out = args.dest / f["path"]
        print(f"{f['path']} ({f['bytes'] / 1e6:.1f} MB)")
        fetch(RAW + f["path"], out, f["bytes"])
        if git_blob_sha1(out) != f["git_sha1"]:
            out.unlink()
            raise SystemExit(f"git blob SHA-1 mismatch for {f['path']} (deleted, re-run to retry)")
        digest = sha256(out)
        if f.get("sha256") and f["sha256"] != digest:
            raise SystemExit(f"SHA-256 mismatch for {f['path']}")
        if not f.get("sha256"):
            if not args.pin:
                raise SystemExit(f"{f['path']} has no pinned SHA-256; re-run with --pin to record it")
            f["sha256"] = digest
            changed = True
        if out.suffix == ".zip" and not args.no_extract:
            target = out.parent
            if not (target / attack).exists():
                with zipfile.ZipFile(out) as z:
                    for m in z.namelist():  # zip-slip guard
                        if m.startswith(("/", "\\")) or ".." in Path(m).parts or ":" in m:
                            raise SystemExit(f"unsafe member {m} in {out}")
                    z.extractall(target)
    if changed:
        MANIFEST.write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
        print("pinned SHA-256 digests written to", MANIFEST)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
