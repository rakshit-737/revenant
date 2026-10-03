#!/usr/bin/env python3
"""Copy single-source Markdown blocks into README.md so README and the docs site never drift.

Each block lives once under ``docs/snippets/`` (the docs pages include it with
pymdownx.snippets) and is copied into README.md between
``<!-- NAME:start -->`` and ``<!-- NAME:end -->``. The headline table comes
from ``results/headline.md`` (written by ``benchmarks/make_figures.py``).

Usage::

    python scripts/sync_docs.py          # rewrite README.md
    python scripts/sync_docs.py --check  # exit 1 if README.md is out of date (CI)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOCKS = {
    "headline": ROOT / "results" / "headline.md",
    "limitations": ROOT / "docs" / "snippets" / "limitations.md",
    "roadmap": ROOT / "docs" / "snippets" / "roadmap.md",
}


def _body(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"^<!--.*?-->\n", "", text)  # generated-by notes stay out of the README
    return text if text.endswith("\n") else text + "\n"


def synced(readme: str) -> str:
    """Return README text with every marked block replaced by its single source."""
    for name, src in BLOCKS.items():
        if not src.exists():
            continue
        body = _body(src)
        readme = re.sub(rf"(<!-- {name}:start -->\n).*?(<!-- {name}:end -->)",
                        lambda m, body=body: m.group(1) + body + m.group(2), readme, flags=re.S)
    return readme


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail instead of rewriting")
    a = ap.parse_args(argv)
    readme = ROOT / "README.md"
    cur = readme.read_text(encoding="utf-8")
    new = synced(cur)
    if a.check:
        if new != cur:
            print("README.md is out of sync with docs/snippets/ or results/headline.md: "
                  "run python scripts/sync_docs.py", file=sys.stderr)
            return 1
        print("README.md blocks in sync")
        return 0
    if new != cur:
        readme.write_text(new, encoding="utf-8")
        print("README.md updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
