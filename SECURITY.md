# Security Policy - REVENANT

## Intended use

REVENANT is a **defensive, analytical, lab-only** DFIR tool. It reconstructs
forensic timelines from artifacts you are authorized to analyze. It:

- reads and reconstructs artifacts; it **never mutates source evidence**;
- generates **no offensive/exploit code** and targets no third-party systems;
- ships only synthetic fixtures plus one field-trimmed public OTRF log capture
  (text logs, no binaries). Benchmark corpora are *downloaded* public event
  logs (OTRF Security-Datasets, EVTX-ATTACK-SAMPLES). They contain attacker
  command lines as text but no executable malware, and some endpoint AV
  products quarantine them anyway. Leave AV enabled: REVENANT records
  unreadable artefacts instead of failing.

Do not use it against systems or data you are not authorized to examine.

## Safe defaults

- The core engine runs **in-memory** (networkx / pure-Python fallback). Neo4j,
  the API and PDF export are optional extras.
- Evidence XML is parsed with **defusedxml** (entity-expansion / XXE safe).
- The API only reads beneath `REVENANT_EVIDENCE_ROOT`. Client paths are
  validated lexically (no absolute, UNC, drive or `..` inputs) before any
  filesystem access, and symlinks/junctions inside evidence are never followed.
  It binds to `127.0.0.1` by default (`serve` refuses other addresses without
  `--allow-remote`), serves only loopback `Host` headers (DNS-rebinding guard),
  refuses cross-origin POSTs and caps request bodies at 64 KiB of received bytes
  (chunked bodies included). It has no
  authentication: never expose it on a network; with Docker publish the port
  as `-p 127.0.0.1:8000:8000`.
- The UI's two CDN scripts are pinned with Subresource Integrity hashes.
- The custody store is append-only (SQLite triggers) and `verify` opens it
  read-only. Offline edits *inside* the chain are detected by the hash chain; a
  dropped trigger fails verification. Truncating the tail or rewriting the
  whole chain is detected only against an external anchor: the ledger head and
  record count printed in each report (`verify --expect-head --expect-count`).

## Supply-chain / CI

The CI workflow (`.github/workflows/ci.yml`) runs on every push and PR:

- `ruff` lint and the test suite on Python 3.10-3.14, plus a CLI smoke test on
  the real OTRF fixture;
- **SAST** via `bandit` (blocking at medium severity and above);
- **dependency vulnerability scan** via `pip-audit`;
- **secret scan** via `gitleaks`.

## Reporting a vulnerability

This is a student/portfolio project. Please report privately through a GitHub
security advisory: <https://github.com/rakshit-737/revenant-dfir-timeline/security/advisories/new>.
Do not open a public issue. There is no production deployment and no SLA.

## Handling real evidence

If you adapt REVENANT for real casework:

1. Work on **copies** of forensic images; preserve originals with independent
   hashing (this tool's ledger complements, not replaces, your acquisition
   chain of custody).
2. Keep the analysis host isolated.
3. Treat all confidence grades as **analyst decision support**, not conclusions.
