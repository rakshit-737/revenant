"""REVENANT command-line interface.

Commands::

  revenant scenarios                          list built-in synthetic scenarios
  revenant demo [--scenario NAME]             run a scenario end-to-end, print report
  revenant analyze PATH [PATH ...]            analyse artefacts (OTRF JSON, .evtx, plaso
                                              json_line/l2tcsv, Volatility dir, auth.log)
                                              or a legacy [[kind, record], ...] JSON file
        --kind K   --format md|html|json|cypher   --out FILE   --pdf FILE
        --ledger custody.sqlite   --top N   --include-noisy
  revenant verify FILE|LEDGER.sqlite          custody-ledger integrity check
  revenant serve [--host --port]              FastAPI + timeline/graph UI
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import pipeline
from .generators import SCENARIOS
from .report import generate_html, generate_report


def _load_records(path: str) -> list[tuple[str, dict[str, Any]]]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    records: list[tuple[str, dict[str, Any]]] = []
    for item in data:
        if isinstance(item, dict):
            records.append((item["kind"], item["record"]))
        else:
            records.append((item[0], item[1]))
    return records


def _is_legacy_records(path: str) -> bool:
    p = Path(path)
    if not p.is_file() or p.suffix.lower() != ".json":
        return False
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(4096).lstrip()
    if not head.startswith("["):
        return False
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    first = data[0] if isinstance(data, list) and data else None
    return (isinstance(first, list) and len(first) == 2 and isinstance(first[0], str)) or (
        isinstance(first, dict) and "kind" in first and "record" in first
    )


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

    a = sub.add_parser("analyze", help="analyse artefacts or a legacy records JSON file")
    a.add_argument("paths", nargs="+")
    a.add_argument("--kind", choices=["otrf", "evtx", "plaso", "volatility", "authlog"])
    a.add_argument("--format", choices=["md", "html", "json", "cypher"], default="md")
    a.add_argument("--out", help="write the output here instead of stdout")
    a.add_argument("--pdf", help="also render the report to this PDF (needs WeasyPrint)")
    a.add_argument("--ledger", help="append the custody ledger to this SQLite store")
    a.add_argument("--top", type=int, default=5)
    a.add_argument("--include-noisy", action="store_true", help="also ingest Sysmon 7 image loads")

    v = sub.add_parser("verify", help="verify custody-ledger integrity")
    v.add_argument("file", help="legacy records JSON, or a .sqlite custody store")

    s = sub.add_parser("serve", help="start the API + UI (needs the [api] extra)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    return p


def _emit(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _analyze(args: argparse.Namespace) -> int:
    if len(args.paths) == 1 and _is_legacy_records(args.paths[0]):
        analysis = pipeline.run(_load_records(args.paths[0]))
    else:
        analysis = pipeline.analyze_paths(args.paths, kind=args.kind, include_noisy=args.include_noisy)
    if args.format == "md":
        text = generate_report(analysis, top=args.top)
    elif args.format == "html":
        text = generate_html(analysis, top=args.top)
    elif args.format == "json":
        from .export import to_json

        text = to_json(analysis, top=max(args.top, 20))
    else:
        from .export import to_cypher

        text = to_cypher(analysis, top=max(args.top, 20))
    _emit(text, args.out)
    if args.pdf:
        from .report import write_pdf

        write_pdf(analysis, args.pdf, top=args.top)
        print(f"wrote {args.pdf}", file=sys.stderr)
    if args.ledger:
        from .custody_store import append_ledger

        n = append_ledger(analysis.ledger, args.ledger)
        print(f"custody: appended {n} records to {args.ledger}", file=sys.stderr)
    return 0


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
        return _analyze(args)

    if args.command == "verify":
        if args.file.endswith((".sqlite", ".db")):
            from .custody_store import load_ledger

            ledger = load_ledger(args.file)
        else:
            ledger = pipeline.run(_load_records(args.file)).ledger
        ok = ledger.verify()
        print(f"custody ledger records: {len(ledger.records)}")
        print(f"tamper-evident chain intact: {ok}")
        return 0 if ok else 2

    if args.command == "serve":  # pragma: no cover - starts a server
        import uvicorn

        from .api import app

        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
