"""REVENANT command-line interface.

Commands:
  revenant scenarios                 list built-in synthetic scenarios
  revenant demo [--scenario NAME]    run a scenario end-to-end, print report
  revenant analyze FILE.json         analyze a JSON list of [kind, record] pairs
  revenant verify FILE.json          ingest + report custody-ledger integrity
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import pipeline
from .generators import SCENARIOS
from .report import generate_report


def _load_records(path: str) -> list[tuple[str, dict[str, Any]]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    records: list[tuple[str, dict[str, Any]]] = []
    for item in data:
        if isinstance(item, dict):
            records.append((item["kind"], item["record"]))
        else:
            records.append((item[0], item[1]))
    return records


def _run_and_report(records, top: int = 5) -> str:
    analysis = pipeline.run(records)
    return generate_report(analysis, top=top)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="revenant", description="Forensic timeline reconstruction (lab-only).")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("scenarios", help="list built-in synthetic scenarios")

    d = sub.add_parser("demo", help="run a built-in scenario end-to-end")
    d.add_argument("--scenario", default="intrusion", choices=sorted(SCENARIOS))
    d.add_argument("--top", type=int, default=5)

    a = sub.add_parser("analyze", help="analyze a JSON records file")
    a.add_argument("file")
    a.add_argument("--top", type=int, default=5)

    v = sub.add_parser("verify", help="ingest and verify custody ledger integrity")
    v.add_argument("file")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "scenarios":
        for name in sorted(SCENARIOS):
            print(name)
        return 0

    if args.command == "demo":
        records = SCENARIOS[args.scenario]()
        print(_run_and_report(records, top=args.top))
        return 0

    if args.command == "analyze":
        records = _load_records(args.file)
        print(_run_and_report(records, top=args.top))
        return 0

    if args.command == "verify":
        records = _load_records(args.file)
        analysis = pipeline.run(records)
        ok = analysis.ledger.verify()
        print(f"custody ledger records: {len(analysis.ledger.records)}")
        print(f"tamper-evident chain intact: {ok}")
        return 0 if ok else 2

    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
