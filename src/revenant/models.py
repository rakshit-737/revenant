"""Typed contracts for REVENANT.

Every forensic fact flows through these models. The schema is deliberately
small and frozen-ish: an ``Event`` is an (actor, action, object, time) tuple
tied back to the raw artifact that produced it, plus an integrity hash. All
downstream reasoning (edges, chains, narratives) references events by id, so a
claim can always be traced to evidence.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class SourceReliability(str, enum.Enum):
    """Admiralty-code style source reliability (A=most reliable ... F=unknown)."""

    A = "A"  # completely reliable
    B = "B"  # usually reliable
    C = "C"  # fairly reliable
    D = "D"  # not usually reliable
    E = "E"  # unreliable
    F = "F"  # cannot be judged

    @property
    def weight(self) -> float:
        return {
            "A": 1.0,
            "B": 0.85,
            "C": 0.65,
            "D": 0.4,
            "E": 0.2,
            "F": 0.5,  # unknown -> neutral-ish, never fully trusted
        }[self.value]


class EventType(str, enum.Enum):
    """Normalized event categories used by the causal rule engine."""

    PROCESS_START = "process_start"
    PROCESS_STOP = "process_stop"
    FILE_WRITE = "file_write"
    FILE_READ = "file_read"
    FILE_DELETE = "file_delete"
    REGISTRY_SET = "registry_set"
    NETWORK_CONNECT = "network_connect"
    LOGON = "logon"
    LOGOFF = "logoff"
    DNS_QUERY = "dns_query"
    OTHER = "other"


class KillChainStage(str, enum.Enum):
    """Lockheed-Martin cyber kill chain stages used for chain classification."""

    RECON = "reconnaissance"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"  # persistence
    C2 = "command_and_control"
    ACTIONS = "actions_on_objectives"  # exfil / impact


class ConfidenceGrade(str, enum.Enum):
    """Human-facing confidence bands for a reconstructed chain."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"

    @classmethod
    def from_score(cls, score: float) -> "ConfidenceGrade":
        if score >= 0.85:
            return cls.CONFIRMED
        if score >= 0.65:
            return cls.HIGH
        if score >= 0.4:
            return cls.MEDIUM
        return cls.LOW


# --------------------------------------------------------------------------- #
# Core records
# --------------------------------------------------------------------------- #
class Event(BaseModel):
    """A single normalized forensic event.

    ``event_id`` is stable and derived from content by the integrity layer.
    ``integrity_hash`` binds the event to its raw source bytes.
    """

    event_id: str
    timestamp: datetime
    event_type: EventType
    actor: str  # e.g. "user:alice" or "process:4123:powershell.exe"
    action: str  # short verb, e.g. "spawned", "wrote", "connected"
    object: str  # target, e.g. "file:C:/tmp/x.dll" or "ip:10.0.0.5:443"
    source_artifact: str  # which artifact produced this (e.g. "sysmon", "plaso")
    source_reliability: SourceReliability = SourceReliability.C
    integrity_hash: Optional[str] = None
    # free-form normalized attributes (pid, ppid, image, hashes, host...)
    attributes: dict[str, str] = Field(default_factory=dict)

    @field_validator("actor", "object", "action", "source_artifact")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("field must be non-empty")
        return v.strip()

    def canonical(self) -> str:
        """Deterministic string used for hashing / stable ids."""
        attrs = ";".join(f"{k}={self.attributes[k]}" for k in sorted(self.attributes))
        return "|".join(
            [
                self.timestamp.isoformat(),
                self.event_type.value,
                self.actor,
                self.action,
                self.object,
                self.source_artifact,
                attrs,
            ]
        )


class CausalEdge(BaseModel):
    """A typed causal link inferred between two events."""

    src_event_id: str
    dst_event_id: str
    relation: str  # e.g. "spawned", "wrote", "authenticated_as"
    rule_name: str  # which rule produced this edge (explainability)
    time_delta_s: float  # seconds between src and dst
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class ProvenanceChain(BaseModel):
    """An ordered candidate incident narrative (sequence of events)."""

    chain_id: str
    event_ids: list[str]
    edges: list[CausalEdge] = Field(default_factory=list)
    stages: list[KillChainStage] = Field(default_factory=list)
    confidence_score: float = Field(ge=0.0, le=1.0, default=0.0)
    grade: ConfidenceGrade = ConfidenceGrade.LOW
    tampering_flags: list[str] = Field(default_factory=list)


class CustodyRecord(BaseModel):
    """Append-only chain-of-custody ledger entry."""

    seq: int
    timestamp: datetime
    action: str  # "ingest", "verify", "reconstruct", "report"
    event_id: Optional[str] = None
    artifact: Optional[str] = None
    digest: str  # hash of the payload this record commits to
    prev_digest: str  # hash of the previous ledger record (tamper-evident chain)
    record_hash: str  # hash over this record's fields


class TamperingIndicator(BaseModel):
    """A cross-artifact inconsistency suggesting anti-forensics."""

    indicator: str  # e.g. "timestomp", "log_gap", "hash_mismatch"
    detail: str
    event_ids: list[str] = Field(default_factory=list)
    severity: str = "medium"  # low|medium|high
