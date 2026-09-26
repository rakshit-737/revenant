#!/usr/bin/env python3
"""Rebuild the small real-data test fixture from a downloaded OTRF capture.

``tests/fixtures/otrf_psexec_lsa_secrets.jsonl`` is a field-trimmed copy of
OTRF Security-Datasets ``cmd_psexec_lsa_secrets_dump`` (MIT licence,
(c) Open Threat Research Forge). Only the fields REVENANT's mapper reads are
kept, so the fixture stays small while every row is a genuine record.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmarks"))
from common import OTRF_ATOMIC  # noqa: E402

SRC = OTRF_ATOMIC / "windows" / "credential_access" / "host" / "cmd_psexec_lsa_secrets_dump"
DST = ROOT / "tests" / "fixtures" / "otrf_psexec_lsa_secrets.jsonl"
DROP = {"Message", "Keywords", "ProviderGuid", "SourceModuleName", "SourceModuleType", "port", "tags",
        "@version", "Opcode", "OpcodeValue", "Severity", "SeverityValue", "Task", "Version", "Category",
        "EventType", "EventReceivedTime", "ThreadID", "UserID", "AccountType", "AccountName", "Domain",
        "Description", "Company", "Product", "FileVersion", "OriginalFileName", "CallTrace", "ActivityID",
        "host", "ExecutionProcessID"}
KEEP_EVENT_TYPES_ANYWAY = {"EventType"}  # Sysmon 12/13 use EventType for the registry op


def main() -> int:
    files = sorted(SRC.glob("*.json"))
    if not files:
        print(f"capture not found under {SRC}; run scripts/download_data.py", file=sys.stderr)
        return 1
    out = []
    with files[0].open(encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            ch = str(r.get("Channel", "")).lower()
            if "sysmon" in ch and str(r.get("EventID")) == "7":
                continue  # image loads: bulky and not used by default
            out.append({k: v for k, v in r.items()
                        if k not in DROP or (k in KEEP_EVENT_TYPES_ANYWAY and "sysmon" in ch)})
    DST.parent.mkdir(parents=True, exist_ok=True)
    DST.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in out), encoding="utf-8")
    print(f"wrote {DST} ({len(out)} rows, {DST.stat().st_size / 1024:.0f} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
