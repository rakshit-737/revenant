# CLI & API reference

## Command line

```
revenant scenarios                          list built-in synthetic scenarios
revenant demo [--scenario NAME]             run a scenario end-to-end, print report
revenant analyze PATH [PATH ...]            analyse artefacts (OTRF JSON, .evtx, plaso
                                            json_line/l2tcsv, Volatility dir, auth.log)
     --kind K  --format md|html|json|cypher  --out FILE  --pdf FILE
     --ledger custody.sqlite  --top N  --include-noisy
revenant verify FILE|LEDGER.sqlite          custody-ledger integrity check
revenant serve [--host --port]              FastAPI + timeline/graph UI
```

## HTTP API

When run with `revenant serve` (needs the `api` extra), the service exposes:

| Method & path | Purpose |
| --- | --- |
| `GET /` | single-page timeline + causal-graph UI |
| `GET /api/health` | liveness |
| `GET /api/scenarios` | built-in synthetic scenarios |
| `POST /api/cases/scenario/{name}` | analyse a synthetic scenario |
| `POST /api/cases/path` | analyse artefacts under the evidence root |
| `GET /api/cases` | list cases |
| `GET /api/cases/{id}` | stories, events, edges, indicators (JSON) |
| `GET /api/cases/{id}/report.md` / `.html` | court-style report |
| `GET /api/cases/{id}/cypher` | Neo4j export |
| `GET /api/cases/{id}/custody` | custody ledger + verification |

The service only reads evidence, only below `REVENANT_EVIDENCE_ROOT`, and binds to
localhost by default.

## Python API

::: revenant.pipeline
    options:
      heading_level: 3

::: revenant.models
    options:
      heading_level: 3

::: revenant.confidence
    options:
      heading_level: 3

::: revenant.integrity
    options:
      heading_level: 3

::: revenant.custody_store
    options:
      heading_level: 3

::: revenant.export
    options:
      heading_level: 3
