#!/usr/bin/env python3
"""Download the public DFIR datasets REVENANT is benchmarked on.

Sources (all public, downloaded -- never redistributed in this repo):

* OTRF Security-Datasets (MIT) -- Windows atomic host datasets (Sysmon +
  Security + PowerShell event logs as JSON lines) and the APT29 ATT&CK-Evals
  day-1 compound dataset, pinned to a commit.
* OTRF compound captures (opt-in groups): ``otrf-lsass`` (7 LSASS-dump
  campaign host logs), ``otrf-log4shell`` (2) and ``otrf-apt29-day2``
  (43 MB compressed, ~1.7 GB of JSON -- run it in GitHub Actions). These
  are verified against the git blob SHA-1 of the pinned OTRF tree.
* EVTX-ATTACK-SAMPLES by @sbousseaden (GPL-3.0) -- raw ``.evtx`` files grouped
  by ATT&CK tactic, pinned to a commit. Used only to exercise the binary EVTX
  parser; nothing from it is committed here.

Every file is verified against ``data/manifest.json`` (SHA-256 and/or git
blob SHA-1 + size); entries with no pin are refused unless ``--pin``. Run
with ``--refresh-manifest`` to rebuild the manifest from the pinned commits
(requires network access to api.github.com).

Usage::

    python scripts/download_data.py                     # default dest
    python scripts/download_data.py --dest D:/data/revenant
    python scripts/download_data.py --only otrf-atomic  # subset
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data" / "manifest.json"
DEFAULT_DEST = Path(os.environ.get("REVENANT_DATA", ROOT.parent.parent / "datasets" / "revenant"))

OTRF_REPO = "OTRF/Security-Datasets"
OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
EVTX_REPO = "sbousseaden/EVTX-ATTACK-SAMPLES"
EVTX_COMMIT = "4ceed2f4706daf601c212a8f91c113dd85349a2c"
OPT_IN_GROUPS = {"otrf-apt29-day2", "otrf-lsass", "otrf-log4shell"}  # large; fetch with --only
MAX_ATOMIC_BYTES = 8_000_000  # skip the few very large atomic captures


def _get(url: str, retries: int = 4) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "revenant-downloader"})
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        # only to lift the API rate limit; never forwarded on redirects
        req.add_unredirected_header("Authorization", f"Bearer {token}")
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310  # nosec B310 - fixed https URLs
                return resp.read()
        except (OSError, http.client.HTTPException) as exc:  # timeouts / resets: retry
            if attempt == retries:
                raise
            print(f"  retry {attempt}/{retries - 1} after {exc!r}", file=sys.stderr)
            time.sleep(2 * attempt)
    raise RuntimeError("unreachable")


def _git_sha1(path: Path) -> str:
    """Git blob id: lets a first download be verified against the pinned commit's tree."""
    h = hashlib.sha1(f"blob {path.stat().st_size}\0".encode(), usedforsecurity=False)
    h.update(path.read_bytes())
    return h.hexdigest()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def refresh_manifest() -> dict:
    """Enumerate files at the pinned commits and build a fresh manifest."""
    tree_url = f"https://api.github.com/repos/{OTRF_REPO}/git/trees/{OTRF_COMMIT}?recursive=1"
    tree = json.loads(_get(tree_url))["tree"]
    raw = f"https://raw.githubusercontent.com/{OTRF_REPO}/{OTRF_COMMIT}/"
    entries = []
    for node in tree:
        p, size = node["path"], node.get("size", 0)
        if node["type"] != "blob":
            continue
        if p.startswith("datasets/atomic/_metadata/SDWIN-") and p.endswith(".yaml"):
            group = "otrf-metadata"
        elif (
            p.startswith("datasets/atomic/windows/")
            and "/host/" in p
            and (p.endswith(".zip") or p.endswith(".tar.gz"))
            and size <= MAX_ATOMIC_BYTES
        ):
            group = "otrf-atomic"
        elif p == "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip":
            group = "otrf-apt29"
        elif p == "datasets/compound/apt29/day2/apt29_evals_day2_manual.zip":
            group = "otrf-apt29-day2"
        elif p.startswith("datasets/compound/LSASS_campaign_") and p.endswith("_lsass_memory_dump.zip"):
            group = "otrf-lsass"  # host logs only; the pcaps are skipped
        elif p.startswith("datasets/compound/Log4Shell/") and p.split("/")[-1].startswith(("sysmon_", "securityauditing_")):
            group = "otrf-log4shell"
        else:
            continue
        entries.append({"group": group, "path": p.replace("datasets/", "otrf/", 1), "url": raw + p,
                        "git_sha1": node["sha"]})
    entries.append(
        {
            "group": "evtx-attack-samples",
            "path": "evtx-attack-samples.zip",
            "url": f"https://codeload.github.com/{EVTX_REPO}/zip/{EVTX_COMMIT}",
        }
    )
    return {
        "sources": {
            "otrf": {"repo": OTRF_REPO, "commit": OTRF_COMMIT, "license": "MIT"},
            "evtx-attack-samples": {"repo": EVTX_REPO, "commit": EVTX_COMMIT, "license": "GPL-3.0"},
        },
        "files": entries,
    }


def extract(archive: Path) -> None:
    if not (archive.suffix == ".zip" or archive.name.endswith(".tar.gz")):
        return
    out = archive.parent / (archive.name.split(".")[0])
    if out.exists():
        return
    out.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            for m in zf.infolist():
                target = (out / m.filename).resolve()
                if not target.is_relative_to(out.resolve()):
                    raise RuntimeError(f"unsafe path in {archive}: {m.filename}")
            zf.extractall(out)  # nosec B202 - every member checked above
    elif archive.name.endswith(".tar.gz"):
        with tarfile.open(archive) as tf:
            tf.extractall(out, filter="data")  # nosec B202 - "data" filter rejects unsafe members


def _write_manifest(manifest: dict) -> None:
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    print(f"[manifest] wrote {MANIFEST}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    ap.add_argument("--only", action="append", help="restrict to manifest group(s)")
    ap.add_argument("--refresh-manifest", action="store_true")
    ap.add_argument("--no-extract", action="store_true")
    ap.add_argument("--pin", action="store_true",
                    help="trust the first download of entries that carry no git_sha1/sha256 pin")
    args = ap.parse_args(argv)

    if args.refresh_manifest or not MANIFEST.exists():
        manifest = refresh_manifest()
        _write_manifest(manifest)
    else:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    dest: Path = args.dest
    dest.mkdir(parents=True, exist_ok=True)
    total, bad, blocked, dirty = 0, 0, [], False
    for entry in manifest["files"]:
        if args.only and entry["group"] not in args.only:
            continue
        if not args.only and entry["group"] in OPT_IN_GROUPS:
            continue
        target = dest / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            if not target.exists():
                print(f"[get] {entry['path']}", flush=True)
                tmp = target.with_name(target.name + ".part")
                tmp.write_bytes(_get(entry["url"]))
                tmp.replace(target)
            digest, size = _sha256(target), target.stat().st_size
            if entry.get("sha256"):
                if digest != entry["sha256"]:
                    print(f"[FAIL] checksum mismatch (deleted): {entry['path']}", file=sys.stderr)
                    target.unlink()
                    bad += 1
                    continue
            else:
                if not entry.get("git_sha1") and not args.pin:
                    print(f"[FAIL] no pinned digest for {entry['path']} (pass --pin to trust first fetch)",
                          file=sys.stderr)
                    target.unlink()
                    bad += 1
                    continue
                if entry.get("git_sha1") and _git_sha1(target) != entry["git_sha1"]:
                    print(f"[FAIL] git blob mismatch (deleted): {entry['path']}", file=sys.stderr)
                    target.unlink()
                    bad += 1
                    continue
                entry["sha256"], entry["bytes"] = digest, size  # first fetch pins the hash
                dirty = True
            total += size
            if not args.no_extract:
                extract(target)
        except OSError as exc:
            # Endpoint AV may quarantine captures whose log text contains
            # attack-tool strings (e.g. Mimikatz command lines). They are
            # logs, not binaries: report and continue rather than disable AV.
            print(f"[blocked] {entry['path']}: {exc}", file=sys.stderr, flush=True)
            blocked.append(entry["path"])
    if dirty:  # pin first-seen hashes so every later fetch is verified
        _write_manifest(manifest)
    print(f"[done] {total / 1e6:.1f} MB verified under {dest} "
          f"({bad} checksum failures, {len(blocked)} blocked by the OS/AV)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
