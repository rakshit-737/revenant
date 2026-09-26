# Architecture

```mermaid
flowchart LR
  subgraph Evidence["Evidence: read-only"]
    OTRF["OTRF / Mordor JSON"] --> P
    EVTX[".evtx via python-evtx"] --> P
    PL["plaso json_line / l2tcsv"] --> P
    VOL["Volatility 3 JSON"] --> P
    AUTH["auth.log"] --> P
  end
  P["parsers/*<br/>map to Event + SHA-256"] --> L[("custody ledger<br/>hash chain to SQLite")]
  P --> G[("provenance graph<br/>networkx or in-memory")]
  G --> F["fusion<br/>corroborations"]
  F --> R["rule engine<br/>GUID to PID to cross-entity to fallback"]
  R --> AF["anti-forensics scan"]
  R --> AT["ATT&CK heuristics + rarity"]
  AT --> S["story reconstructor"]
  AF --> S
  S --> C["confidence scorer<br/>calibrated edges"]
  C --> OUT{"outputs"}
  OUT --> MD["Markdown / HTML / PDF report"]
  OUT --> JS["JSON"]
  OUT --> CY["Cypher to Neo4j"]
  OUT --> API["FastAPI + vis-timeline UI"]
```

## Module map

| Module | Responsibility |
| --- | --- |
| `models.py` | Pydantic contracts: `Event`, `CausalEdge`, `IncidentStory`, `CustodyRecord`, `TamperingIndicator` |
| `integrity.py` | Canonical event hashing, stable ids, in-memory hash-chained ledger |
| `custody_store.py` | Append-only SQLite persistence and offline verification |
| `entities.py` | Lossy identity keys: PID, image, host, user (ADR 0003) |
| `parsers/` | One connector per artefact family; `windows.py` is the shared Windows mapper |
| `graph.py` | Temporal provenance graph with corroboration side-table |
| `fusion.py` | Same fact seen by several artefacts becomes one primary node plus corroborations |
| `rules.py` | Indexed causal rule engine and packaged per-rule calibration (ADR 0002) |
| `attack.py` | ATT&CK heuristic tags and per-case rarity, combined into event suspicion |
| `antiforensics.py` | Tampering indicators |
| `stories.py` | Story roots, subtrees, suspicion/confidence, unknown windows (ADR 0004) |
| `confidence.py` | Reliability × corroboration × temporal fit × edge strength, with tamper penalty |
| `report.py` | Court-style report (Markdown to HTML, optional WeasyPrint PDF) |
| `export.py` | JSON, Cypher and live Neo4j push |
| `api.py`, `web/` | FastAPI and a single-page timeline/graph UI |
| `reconstruct.py`, `normalize.py`, `generators.py` | v0.1 path view, legacy normaliser, synthetic scenarios |

## Trust boundaries

- Evidence is only ever **read**. The API only reads beneath
  `REVENANT_EVIDENCE_ROOT` and binds to localhost by default.
- XML from `.evtx` is parsed with `defusedxml` when available.
- Unreadable artefacts are recorded in the ledger and the report, never
  silently dropped.
