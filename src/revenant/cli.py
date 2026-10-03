"""REVENANT command-line interface.

Commands::

  revenant scenarios                          list built-in synthetic scenarios
  revenant demo [--scenario NAME]             run a scenario end-to-end, print report
  revenant analyze PATH [PATH ...]            analyse artefacts (OTRF JSON, .evtx, plaso
                                              json_line/l2tcsv, Volatility dir, auth.log)
                                              or a legacy [[kind, record], ...] JSON file
        --kind K   --format md|html|json|cypher   --out FILE   --pdf FILE
        --ledger custody.sqlite   --top N   --include-noisy
  revenant verify FILE|LEDGER.sqlite          custody-ledger integrity check (read-only;
        --expect-head HASH --expect-count N   external anchors also detect truncation)
  revenant serve [--host --port]              FastAPI + timeline/graph UI
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .generators import SCENARIOS

# the engine (pydantic, networkx) is imported only by commands that need it, so
# --version and --help answer immediately


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
    from . import pipeline
    from .report import generate_report

    analysis = pipeline.run(records)
    return generate_report(analysis, top=top)


def build_parser() -> argparse.ArgumentParser:
    """Build the ``revenant`` command-line argument parser."""
    from .parsers import KINDS

    p = argparse.ArgumentParser(prog="revenant", description="Forensic timeline reconstruction (lab-only).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("scenarios", help="list built-in synthetic scenarios")

    d = sub.add_parser("demo", help="run a built-in scenario end-to-end")
    d.add_argument("--scenario", default="intrusion", choices=sorted(SCENARIOS), help="scenario (default: intrusion)")
    d.add_argument("--top", type=int, default=5, help="number of stories in the report (default: 5)")

    a = sub.add_parser("analyze", help="analyse artefacts or a legacy records JSON file")
    a.add_argument("paths", nargs="+", help="artefact files or directories (each must exist)")
    a.add_argument("--kind", choices=KINDS, help="artefact kind (default: auto-detect)")
    a.add_argument("--host", default="", help="host name for host-less artefacts (Volatility, auditd)")
    a.add_argument("--format", choices=["md", "html", "json", "cypher"], default="md",
                   help="output format (default: md)")
    a.add_argument("--out", help="write the output here instead of stdout")
    a.add_argument("--pdf", help="also render the report to this PDF (needs WeasyPrint)")
    a.add_argument("--ledger", help="persist the custody ledger to a new SQLite store (or one created "
                   "from this same ledger); a store holding another case is refused before any report is written")
    a.add_argument("--top", type=int, default=5, help="number of stories in the report (default: 5)")
    a.add_argument("--include-noisy", action="store_true", help="also ingest Sysmon 7 image loads")

    v = sub.add_parser("verify", help="verify custody-ledger integrity")
    v.add_argument("file", help="legacy records JSON, or a .sqlite custody store")
    v.add_argument("--expect-head", help="ledger head hash printed in the report (detects truncation/rewrite)")
    v.add_argument("--expect-count", type=int, help="expected number of ledger records")

    s = sub.add_parser("serve", help="start the API + UI (needs the [api] extra)")
    s.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1; the API has no auth)")
    s.add_argument("--port", type=int, default=8000, help="port (default: 8000)")
    s.add_argument("--allow-remote", action="store_true", help="permit a non-loopback --host (lab networks only)")
    return p


def _emit(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _analyze(args: argparse.Namespace) -> int:
    from . import pipeline
    from .report import generate_html, generate_report

    missing = [x for x in args.paths if not Path(x).exists()]
    if missing:
        print(f"revenant: no such file or directory: {', '.join(missing)}", file=sys.stderr)
        return 2
    if len(args.paths) == 1 and _is_legacy_records(args.paths[0]):
        analysis = pipeline.run(_load_records(args.paths[0]))
    else:
        opts = {"host": args.host} if args.host else {}
        analysis = pipeline.analyze_paths(args.paths, kind=args.kind, include_noisy=args.include_noisy, **opts)
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
    if args.ledger:  # persist custody first: a report must never cite an unpersisted ledger head
        from .custody_store import append_ledger

        n = append_ledger(analysis.ledger, args.ledger)  # ValueError (exit 2, no report) on a foreign store
        print(f"custody: appended {n} records to {args.ledger}", file=sys.stderr)
    _emit(text, args.out)
    if args.pdf:
        from .report import write_pdf

        write_pdf(analysis, args.pdf, top=args.top)
        print(f"wrote {args.pdf}", file=sys.stderr)
    return 0


_EXTRAS = {"uvicorn": "api", "fastapi": "api", "weasyprint": "pdf", "Evtx": "evtx", "defusedxml": "evtx",
           "neo4j": "neo4j"}


def main(argv: list[str] | None = None) -> int:
    """Entry point of the ``revenant`` console script; returns the exit code."""
    args = build_parser().parse_args(argv)
    try:
        return _dispatch(args)
    except ModuleNotFoundError as exc:
        extra = _EXTRAS.get((exc.name or "").split(".")[0])
        hint = f"pip install 'revenant[{extra}]'" if extra else "check your installation"
        print(f"revenant: missing optional dependency {exc.name!r}: {hint}", file=sys.stderr)
        return 2
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"revenant: {exc}", file=sys.stderr)
        return 2


def _dispatch(args: argparse.Namespace) -> int:

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
        if not Path(args.file).is_file():
            print(f"revenant: no such ledger or records file: {args.file}", file=sys.stderr)
            return 2
        problems: list[str] = []
        if args.file.endswith((".sqlite", ".db")):
            from .custody_store import load_ledger, missing_triggers

            ledger = load_ledger(args.file)
            gone = missing_triggers(args.file)
            if gone:
                problems.append(f"append-only trigger(s) missing: {', '.join(sorted(gone))}")
        else:
            from . import pipeline

            ledger = pipeline.run(_load_records(args.file)).ledger
        recs = ledger.records
        if not recs:
            problems.append("ledger is empty: nothing to verify")
        if args.expect_count is not None and len(recs) != args.expect_count:
            problems.append(f"record count {len(recs)} != expected {args.expect_count}")
        if args.expect_head is not None and (not recs or recs[-1].record_hash != args.expect_head):
            problems.append("ledger head does not match --expect-head")
        ok = ledger.verify() and not problems
        print(f"custody ledger records: {len(recs)}")
        if recs:
            print(f"ledger head: {recs[-1].record_hash}")
        for msg in problems:
            print(f"FAIL: {msg}")
        print(f"tamper-evident chain intact: {ok}")
        return 0 if ok else 2

    if args.command == "serve":  # pragma: no cover - starts a server
        if args.host not in ("127.0.0.1", "localhost", "::1") and not args.allow_remote:
            print("revenant: the API has no authentication; refusing to bind a non-loopback address "
                  "without --allow-remote", file=sys.stderr)
            return 2
        import uvicorn

        from .api import app

        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
