# Getting started

## Try it in 60 seconds

- **No install:** the [live demo](demo/index.html) shows a real public OTRF capture.
- **Docker:** `docker run --rm ghcr.io/rakshit-737/revenant:latest demo --scenario intrusion`
- **pip:** `pip install "git+https://github.com/rakshit-737/revenant" && revenant demo --scenario intrusion`

The first story should read `story-907cbcd159 - suspicion 0.91, confidence HIGH (0.75)`.

!!! warning "Not on PyPI"
    `pip install revenant` installs an **unrelated** package with the same name. Install
    from GitHub (as above) or from a release wheel.

## Install

REVENANT is a pure-Python package (3.10–3.14, all tested in CI). Core dependencies are
`pydantic` and `networkx`; everything else is an optional extra.

```bash
git clone https://github.com/rakshit-737/revenant
cd revenant
pip install -e .            # core
pip install -e '.[evtx,api,pdf]'   # raw .evtx, FastAPI UI, PDF reports
```

Optional extras: `evtx` (raw `.evtx` parsing), `api` (FastAPI + UI), `pdf` (WeasyPrint
reports), `neo4j` (live graph push), `bench` (benchmarks and figures), `dev` (tests +
ruff, enough to run the whole suite), `docs` (this site: `mkdocs serve`).

## Run a built-in scenario

The synthetic scenarios need no data download and are the fastest way to see the output.

```bash
revenant scenarios                 # list scenarios
revenant demo --scenario intrusion # full phishing → PowerShell → C2 story
```

## Analyse real artefacts

These run as written from a checkout (committed fixtures):

```bash
revenant analyze tests/fixtures/otrf_psexec_lsa_secrets.jsonl --format md --top 5
revenant analyze tests/fixtures/otrf_psexec_lsa_secrets.jsonl --format html --out report.html --ledger custody.sqlite
revenant analyze tests/fixtures/plaso.jsonl --format json --out case.json
revenant analyze tests/fixtures/auditd_sample.log --kind auditd
revenant verify custody.sqlite     # read-only hash-chain check
```

On your own evidence pass a file or directory: OTRF/Mordor/Sentinel JSON lines, raw `.evtx`,
plaso `json_line`/`l2tcsv`, a Volatility 3 directory, `auth.log` or auditd `audit.log`.
A missing path exits with status 2. `verify` refuses a missing or empty ledger and a ledger
whose append-only triggers were dropped; pass the report's "Ledger head" and record count
(`--expect-head`, `--expect-count`) to also detect truncation or a full rewrite.

Output formats: `md`, `html`, `json`, `cypher`. Add `--pdf report.pdf` (needs the `pdf`
extra) and `--ledger custody.sqlite` to persist an append-only custody ledger.

## Web UI

```bash
pip install -e '.[api,evtx]'
REVENANT_EVIDENCE_ROOT=/path/to/evidence revenant serve
# open http://127.0.0.1:8000
```

The API only *reads* evidence, only below `REVENANT_EVIDENCE_ROOT`, never follows links
inside it, binds to localhost (other addresses need `--allow-remote`), serves only loopback
`Host` headers and refuses cross-origin POSTs. It has no authentication.

A pre-computed, server-less version is published as the [Live demo](demo/index.html).

## Docker

```bash
docker run --rm -p 127.0.0.1:8000:8000 \
  -v "$PWD/tests/fixtures:/evidence:ro" \
  ghcr.io/rakshit-737/revenant:latest
# the API has no authentication: always publish the port on 127.0.0.1
```

Or use `docker compose up api` (see `docker-compose.yml`; set `NEO4J_PASSWORD` first).

## Datasets

Benchmarks pull public corpora with `python scripts/download_data.py` into `$REVENANT_DATA`
(default `../../datasets/revenant`, outside the repo). Every archive is pinned by SHA-256;
unpinned entries are refused. See [Datasets](datasets.md) and [Reproduce](reproduce.md).
