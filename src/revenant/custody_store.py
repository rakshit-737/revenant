"""Persistent, append-only custody ledger (SQLite).

The spec calls for an append-only store (PostgreSQL). SQLite gives the same
guarantees for a single examiner workstation with zero infrastructure:

* ``BEFORE UPDATE`` / ``BEFORE DELETE`` triggers abort any attempt to rewrite
  history through SQL;
* every row still carries the hash chain from `CustodyLedger`, so an
  edit made *around* SQLite (hex-editing the file) is caught by
  `verify_store`.

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


_TRIGGERS = {"custody_no_update", "custody_no_delete"}


def _connect_ro(path: str | Path) -> sqlite3.Connection:
    """Open an existing store read-only; never creates or alters it."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"no such custody store: {p}")
    return sqlite3.connect(f"{p.resolve().as_uri()}?mode=ro", uri=True)


def missing_triggers(path: str | Path) -> set[str]:
    """Append-only triggers absent from the store (a dropped trigger is a tamper sign)."""
    con = _connect_ro(path)
    try:
        have = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    finally:
        con.close()
    return _TRIGGERS - have


def load_ledger(path: str | Path) -> CustodyLedger:
    """Load a stored ledger read-only. Raises FileNotFoundError for a missing path."""
    con = _connect_ro(path)
    try:
        rows = con.execute("SELECT * FROM custody ORDER BY seq").fetchall()
    except sqlite3.DatabaseError as exc:
        raise ValueError(f"{path} is not a REVENANT custody store: {exc}") from exc
    finally:
        con.close()
    ledger = CustodyLedger()
    for seq, ts, action, eid, art, digest, prev, rh in rows:
        ledger._records.append(  # noqa: SLF001 - reconstructing persisted state
            CustodyRecord(seq=seq, timestamp=datetime.fromisoformat(ts), action=action, event_id=eid,
                          artifact=art, digest=digest, prev_digest=prev, record_hash=rh)
        )
    return ledger


def verify_store(path: str | Path, *, expect_head: str | None = None, expect_count: int | None = None) -> bool:
    """Recompute the hash chain of a stored ledger.

    The internal chain alone cannot reveal a truncated tail or a full rewrite;
    pass the head hash / record count printed in the report (an external
    anchor) to detect those too. Missing append-only triggers fail verification.
    """
    ledger = load_ledger(path)
    if not ledger.records or missing_triggers(path):
        return False
    if expect_count is not None and len(ledger.records) != expect_count:
        return False
    if expect_head is not None and ledger.records[-1].record_hash != expect_head:
        return False
    return ledger.verify()
