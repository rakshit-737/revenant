#!/usr/bin/env python3
"""Generate the static /demo/ case files from committed fixtures and synthetic scenarios.

Run by the docs workflow before ``mkdocs build`` so the demo never drifts from
the code. Real cases come first: the committed OTRF PsExec + LSA-secrets capture
(MIT) and the auditd fixture.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from revenant.export import to_dict  # noqa: E402
from revenant.generators import SCENARIOS  # noqa: E402
from revenant.pipeline import analyze_paths, run  # noqa: E402

OUT = ROOT / "docs" / "demo" / "cases"
FIX = ROOT / "tests" / "fixtures"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    cases = [
        ("otrf-psexec-lsa-secrets (real)", "otrf_psexec", lambda: analyze_paths([FIX / "otrf_psexec_lsa_secrets.jsonl"])),
        ("linux-auditd (real format)", "auditd", lambda: analyze_paths([FIX / "auditd_sample.log"], kind="auditd")),
    ] + [(f"{n} (synthetic)", n, (lambda n=n: run(SCENARIOS[n]()))) for n in sorted(SCENARIOS)]
    index = []
    for title, slug, make in cases:
        a = make()
        d = to_dict(a, top=10, include_all_events=True, max_events=1500)
        d["title"] = title
        for x in d["artefacts"]:  # never publish local paths
            x["path"] = Path(x["path"]).name
        (OUT / f"{slug}.json").write_text(json.dumps(d, separators=(",", ":"), default=str), encoding="utf-8")
        index.append({"name": slug, "title": title, "stories": len(a.stories), "events": len(a.events),
                      "indicators": len(a.indicators)})
        print(f"{slug}: {len(a.events)} events, {len(a.stories)} stories, {len(a.indicators)} indicators")
    (OUT / "index.json").write_text(json.dumps(index, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
