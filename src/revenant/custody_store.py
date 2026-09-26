"""Persistent, append-only custody ledger (SQLite).

The spec calls for an append-only store (PostgreSQL). SQLite gives the same
guarantees for a single examiner workstation with zero infrastructure:

* ``BEFORE UPDATE`` / ``BEFORE DELETE`` triggers abort any attempt to rewrite
  history through SQL;
* every row still carries the hash chain from :class:`CustodyLedger`, so an
  edit made *around* SQLite (hex-editing the file) is caught by
  :func:`verify_store`.

The same schema ports to PostgreSQL unchanged apart from the trigger syntax
(see docs/adr/0005-custody-ledger.md).
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from .integrity import CustodyLedger
from .models import CustodyRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS custody (
    seq          INTEGER PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    action       TEXT NOT NULL,
    event_id     TEXT,
    artifact     TEXT,
    digest       TEXT NOT NULL,
    prev_digest  TEXT NOT NULL,
    record_hash  TEXT NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS custody_no_update BEFORE UPDATE ON custody
BEGIN SELECT RAISE(ABORT, 'custody ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS custody_no_delete BEFORE DELETE ON custody
BEGIN SELECT RAISE(ABORT, 'custody ledger is append-only'); END;
"""


def _connect(path: str | Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(path))
    con.executescript(_SCHEMA)
    return con


def append_ledger(ledger: CustodyLedger, path: str | Path) -> int:
    """Append ledger records not yet in the store. Returns rows written.

    The store must be a prefix of ``ledger`` (same hashes); anything else
    means the two histories diverged and is refused.
    """
    con = _connect(path)
    try:
        existing = [r[0] for r in con.execute("SELECT record_hash FROM custody ORDER BY seq")]
        recs = ledger.records
        if existing != [r.record_hash for r in recs[: len(existing)]]:
            raise ValueError("stored custody history diverges from this ledger; refusing to append")
        new = recs[len(existing):]
        with con:
            con.executemany(
                "INSERT INTO custody VALUES (?,?,?,?,?,?,?,?)",
                [(r.seq, r.timestamp.isoformat(), r.action, r.event_id, r.artifact, r.digest,
                  r.prev_digest, r.record_hash) for r in new],
            )
        return len(new)
    finally:
        con.close()


def load_ledger(path: str | Path) -> CustodyLedger:
    con = _connect(path)
    try:
        rows = con.execute("SELECT * FROM custody ORDER BY seq").fetchall()
    finally:
        con.close()
    ledger = CustodyLedger()
    for seq, ts, action, eid, art, digest, prev, rh in rows:
        ledger._records.append(  # noqa: SLF001 - reconstructing persisted state
            CustodyRecord(seq=seq, timestamp=datetime.fromisoformat(ts), action=action, event_id=eid,
                          artifact=art, digest=digest, prev_digest=prev, record_hash=rh)
        )
    return ledger


def verify_store(path: str | Path) -> bool:
    """Recompute the hash chain of a stored ledger."""
    return load_ledger(path).verify()
