# Getting started

## Install

REVENANT is a pure-Python package (3.10–3.14). Core dependencies are `pydantic` and
`networkx`; everything else is an optional extra.

```bash
git clone https://github.com/rakshit-737/revenant
cd revenant
pip install -e .            # core
pip install -e '.[evtx,api,pdf]'   # raw .evtx, FastAPI UI, PDF reports
```

Optional extras: `evtx` (raw `.evtx` parsing), `api` (FastAPI + UI), `pdf` (WeasyPrint
reports), `neo4j` (live graph push), `bench` (benchmarks), `dev` (tests + ruff).

## Run a built-in scenario

The synthetic scenarios need no data download and are the fastest way to see the output.

```bash
revenant scenarios                 # list scenarios
revenant demo --scenario intrusion # full phishing → PowerShell → C2 story
```

## Analyse real artefacts

```bash
# OTRF/Mordor JSON lines, raw .evtx, plaso json_line/l2tcsv, a Volatility 3 dir, or auth.log
revenant analyze evidence.jsonl --format md --top 5
revenant analyze capture.evtx --format html --out report.html
revenant analyze plaso.jsonl --format json --ledger custody.sqlite
revenant verify custody.sqlite     # offline hash-chain integrity check
```

Output formats: `md`, `html`, `json`, `cypher`. Add `--pdf report.pdf` (needs the `pdf`
extra) and `--ledger custody.sqlite` to persist an append-only custody ledger.

## Web UI

```bash
pip install -e '.[api,evtx]'
REVENANT_EVIDENCE_ROOT=/path/to/evidence revenant serve
# open http://127.0.0.1:8000
```

The API only *reads* evidence, only below `REVENANT_EVIDENCE_ROOT`, and binds to localhost.

A pre-computed, server-less version is published as the [Live demo](demo/index.html).

## Docker

```bash
docker run --rm -p 8000:8000 \
  -v "$PWD/tests/fixtures:/evidence:ro" \
  ghcr.io/rakshit-737/revenant:latest serve --host 0.0.0.0 --port 8000
```

Or use `docker compose up api` (see `docker-compose.yml`).

## Datasets

Benchmarks pull public corpora with `python scripts/download_data.py` into `$REVENANT_DATA`
(default `../../datasets/revenant`, outside the repo). Everything is checksum-pinned. See
[Datasets](datasets.md).
