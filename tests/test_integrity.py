from datetime import datetime, timezone

from revenant.integrity import (
    CustodyLedger,
    finalize_event,
    hash_event,
    verify_event,
)
from revenant.models import Event, EventType


def _ev(action="spawned"):
    return Event(
        event_id="pending",
        timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        event_type=EventType.PROCESS_START,
        actor="process:1:a",
        action=action,
        object="process:2:b",
        source_artifact="sysmon",
    )


def test_finalize_sets_stable_id_and_hash():
    e = finalize_event(_ev())
    assert e.integrity_hash and e.event_id.startswith("ev-")
    assert verify_event(e)


def test_hash_changes_with_content():
    assert hash_event(_ev("spawned")) != hash_event(_ev("wrote"))


def test_verify_fails_on_mutation():
    e = finalize_event(_ev())
    tampered = e.model_copy(update={"action": "wrote"})
    assert not verify_event(tampered)


def test_ledger_chain_verifies_and_detects_tamper():
    ledger = CustodyLedger()
    for _ in range(3):
        ledger.record_ingest(finalize_event(_ev()))
    assert ledger.verify()
    # tamper with a middle record's digest
    ledger.records  # snapshot copy, not live
    ledger._records[1] = ledger._records[1].model_copy(update={"digest": "0" * 64})
    assert not ledger.verify()


def test_ledger_is_append_only_sequence():
    ledger = CustodyLedger()
    a = ledger.append("ingest", "d1")
    b = ledger.append("verify", "d2")
    assert a.seq == 0 and b.seq == 1
    assert b.prev_digest == a.record_hash
