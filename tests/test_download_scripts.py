"""Download helpers: git blob ids, manifest schema, archive-path guard."""

from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dd = _load("download_data")
da = _load("download_atlas")


def test_git_blob_sha1_matches_git(tmp_path):
    f = tmp_path / "hello.txt"
    f.write_bytes(b"hello\n")
    # `printf 'hello\n' | git hash-object --stdin`
    assert dd._git_sha1(f) == "ce013625030ba8dba906f756967f9e9ca394464a"
    assert da.git_blob_sha1(f) == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_manifests_are_pinned():
    m = json.loads((ROOT / "data" / "manifest.json").read_text(encoding="utf-8"))
    unpinned = [e["path"] for e in m["files"] if not (e.get("sha256") or e.get("git_sha1"))]
    assert len(unpinned) <= 2, unpinned  # the two AV-blocked Empire archives, refused unless --pin
    a = json.loads((ROOT / "data" / "atlas_manifest.json").read_text(encoding="utf-8"))
    for e in a["files"]:
        assert e["bytes"] > 0 and len(e["git_sha1"]) == 40


def test_zip_slip_refused(tmp_path):
    bad = tmp_path / "evil.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("../escape.txt", "x")
    with pytest.raises(RuntimeError, match="unsafe"):
        dd.extract(bad)
