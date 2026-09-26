# ADR 0005: Hash-chained custody ledger, persisted append-only in SQLite

- Status: accepted (v0.2)
- Date: 2026-09-26

## Context

The spec asks for an append-only custody store (PostgreSQL) and for hashes to
be verified on load. REVENANT runs on a single examiner workstation, often
offline, and a database server is a heavy dependency for that setting.

## Decision

- Integrity lives in the data itself. Each `CustodyRecord` commits to the
  previous record's hash (a hash chain), and every event carries a SHA-256 over
  its canonical form. `CustodyLedger.verify()` recomputes the chain.
- `custody_store.py` persists the ledger to SQLite with `BEFORE UPDATE` and
  `BEFORE DELETE` triggers that abort. A second analysis may only **append** to
  a store whose history is a prefix of its own. A diverging history is
  refused.
- Raw artefacts are hashed **before** parsing (`acquire` records). Files the OS
  refuses to open are recorded as `acquire_failed`, never silently skipped.

## Consequences

- An edit made through SQL is blocked. An edit made around SQL (dropping the
  trigger, hex-editing the file) is **detected** by `verify_store` because the
  hash chain breaks. This is tested.
- The schema ports to PostgreSQL unchanged apart from trigger syntax. Doing so
  would add multi-user access, not stronger integrity.
- The ledger shows tampering but cannot prevent someone replacing the whole
  file. Anchoring the head hash externally (printed in every report as
  "Ledger head") is the mitigation.
