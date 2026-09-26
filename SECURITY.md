# Security Policy - REVENANT

## Intended use

REVENANT is a **defensive, analytical, lab-only** DFIR tool. It reconstructs
forensic timelines from artifacts you are authorized to analyze. It:

- reads and reconstructs artifacts; it **never mutates source evidence**;
- generates **no offensive/exploit code** and targets no third-party systems;
- ships only **synthetic, benign** sample data.

Do not use it against systems or data you are not authorized to examine.

## Safe defaults

- Runs fully **in-memory** (networkx / pure-Python fallback). No Neo4j, Docker,
  or network service is required at runtime.
- No secrets, credentials, or external calls in the core engine.
- Minimal dependencies (`pydantic`, `networkx`); `pytest` for tests.

## Supply-chain / CI

The CI workflow (`.github/workflows/ci.yml`) runs on every push/PR:

- **SAST** via `bandit`
- **dependency vulnerability scan** via `pip-audit`
- **secret scan** via `gitleaks`
- the full test suite on Python 3.10-3.12 plus a CLI smoke test.

## Reporting a vulnerability

This is a student/portfolio project. Please open a private GitHub security
advisory or issue with reproduction steps. There is no production deployment and
no SLA.

## Handling real evidence

If you adapt REVENANT for real casework:

1. Work on **copies** of forensic images; preserve originals with independent
   hashing (this tool's ledger complements, not replaces, your acquisition
   chain of custody).
2. Keep the analysis host isolated.
3. Treat all confidence grades as **analyst decision support**, not conclusions.
