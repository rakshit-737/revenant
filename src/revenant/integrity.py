"""Integrity + chain-of-custody primitives.

Two guarantees:

1. Every event gets a content-derived ``integrity_hash`` and a stable
   ``event_id`` (never trust an id supplied by an artifact).
2. An append-only, tamper-evident custody ledger: each record commits to the
   previous record's hash (a hash chain), so any silent edit or deletion
   breaks verification. The tool never mutates source artifacts.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from .models import CustodyRecord, Event

_GENESIS = "0" * 64


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_event(event: Event) -> str:
    """Deterministic SHA-256 over the event's canonical form."""
    return _sha256(event.canonical())


def stable_event_id(event: Event) -> str:
    """A short, stable id derived from content (first 16 hex of the hash)."""
    return "ev-" + hash_event(event)[:16]


def finalize_event(event: Event) -> Event:
    """Return a copy of ``event`` with integrity_hash and event_id populated."""
    h = hash_event(event)
    return event.model_copy(update={"integrity_hash": h, "event_id": "ev-" + h[:16]})


class CustodyLedger:
    """Append-only tamper-evident ledger of custody records."""

    def __init__(self) -> None:
        self._records: list[CustodyRecord] = []

    @property
    def records(self) -> list[CustodyRecord]:
        """Return a copy of the custody records in ledger order."""
        return list(self._records)

    def _prev_digest(self) -> str:
        return self._records[-1].record_hash if self._records else _GENESIS

    def append(
        self,
        action: str,
        digest: str,
        *,
        event_id: str | None = None,
        artifact: str | None = None,
        when: datetime | None = None,
    ) -> CustodyRecord:
        """Append a hash-chained custody record.

        Parameters
        ----------
        action : str
            What happened (for example ``ingest``).
        digest : str
            SHA-256 of the subject.
        event_id, artifact : str, optional
            What the record refers to.
        when : datetime, optional
            Record time; defaults to now (UTC).

        Returns
        -------
        CustodyRecord
            The new record, chained to the previous one.
        """
        seq = len(self._records)
        prev = self._prev_digest()
        ts = when or datetime.now(timezone.utc)
        body = "|".join(
            [str(seq), ts.isoformat(), action, event_id or "", artifact or "", digest, prev]
        )
        rec = CustodyRecord(
            seq=seq,
            timestamp=ts,
            action=action,
            event_id=event_id,
            artifact=artifact,
            digest=digest,
            prev_digest=prev,
            record_hash=_sha256(body),
        )
        self._records.append(rec)
        return rec

    def record_ingest(self, event: Event) -> CustodyRecord:
        """Append an ``ingest`` record for a finalised event."""
        assert event.integrity_hash, "event must be finalized before ingest"
        return self.append(
            "ingest",
            event.integrity_hash,
            event_id=event.event_id,
            artifact=event.source_artifact,
        )

    def verify(self) -> bool:
        """Recompute the hash chain; return False if any link is broken."""
        prev = _GENESIS
        for i, rec in enumerate(self._records):
            if rec.seq != i or rec.prev_digest != prev:
                return False
            body = "|".join(
                [
                    str(rec.seq),
                    rec.timestamp.isoformat(),
                    rec.action,
                    rec.event_id or "",
                    rec.artifact or "",
                    rec.digest,
                    rec.prev_digest,
                ]
            )
            if _sha256(body) != rec.record_hash:
                return False
            prev = rec.record_hash
        return True


def verify_event(event: Event) -> bool:
    """True if the event's stored integrity_hash matches its content."""
    return bool(event.integrity_hash) and event.integrity_hash == hash_event(event)
