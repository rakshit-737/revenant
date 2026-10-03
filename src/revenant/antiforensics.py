"""Anti-forensics indicators.

Rather than trusting timestamps and logs blindly, REVENANT flags evidence of
tampering as *indicators* that lower the confidence of any chain they touch
and are listed in the report's uncertainty section.

==========================  ===================================================
indicator                   evidence
==========================  ===================================================
``timestomp``               an event carries conflicting MFT vs $LogFile times
``timestomp_sysmon``        Sysmon EID 2: a file's creation time was rewritten
``si_fn_mismatch``          plaso NTFS: $STANDARD_INFORMATION created before
                            $FILE_NAME (classic SetMACE/timestomp artefact)
``log_cleared``             Security 1102 / System 104
``audit_tamper``            4719 audit-policy change, EventLog service / MiniNT
                            / command-line-logging registry edits, wevtutil /
                            auditpol / stop-eventlog command lines
``logging_stopped``         the Event Log service stopped (System 7036) or
                            crashed (System 7034, or WerFault reporting a crash
                            of its svchost), restarted mid-capture (7036
                            running), or logging shut down (Security 1100) --
                            ignored within 5 minutes of a boot/shutdown marker
``clock_change``            Security 4616 with a jump larger than 5 minutes
``record_order``            a channel's record numbers increase while time
                            goes backwards (clock rolled back mid-capture)
``hash_mismatch``           an event's integrity hash no longer matches content
``log_gap``                 a silent window with no artefacts (reported as
                            *unknown*, never fabricated)
==========================  ===================================================
"""

from __future__ import annotations

import re
from collections import defaultdict

from .graph import ProvenanceGraph
from .integrity import verify_event
from .models import Event, EventType, ProvenanceChain, TamperingIndicator
from .parsers.timeutil import parse_ts

_TAMPER_REG = re.compile(
    r"services[\\/]eventlog[\\/](start$|.*[\\/](file|maxsize|retention|autobackuplogfiles)$)"
    r"|control[\\/]minint"
    r"|processcreationincludecmdline_enabled"
    r"|windows[\\/]eventlog[\\/].*[\\/]enabled"
    r"|powershell[\\/](scriptblocklogging[\\/]enablescriptblocklogging|modulelogging[\\/]enablemodulelogging)$",
    re.IGNORECASE,
)
_TAMPER_CMD = re.compile(
    r"wevtutil(\.exe)?\s+(cl|clear-log|sl|set-log)\b|auditpol(\.exe)?\s+/(set|clear|remove)"
    r"|(stop-service|sc(\.exe)?\s+(stop|config)|net\s+stop)\s+.*eventlog|clear-eventlog|remove-eventlog"
    r"|fsutil\s+usn\s+deletejournal",
    re.IGNORECASE,
)


_WER = re.compile(r"(^|[\\/])werfault\.exe$", re.IGNORECASE)
_EVENTLOG_HOST = re.compile(r"svchost\.exe.*\s-s\s+eventlog\b", re.IGNORECASE)


def _ind(kind: str, detail: str, ids: list[str], sev: str) -> TamperingIndicator:
    return TamperingIndicator(indicator=kind, detail=detail, event_ids=ids, severity=sev)


def detect_timestomp(events: list[Event]) -> list[TamperingIndicator]:
    """Flag files whose MFT time disagrees with the `$LogFile` time.

    Parameters
    ----------
    events : list of Event
        Normalised events carrying ``mft_time`` and ``logfile_time`` attributes.

    Returns
    -------
    list of TamperingIndicator
        One ``timestomp`` indicator per disagreeing file.
    """
    out: list[TamperingIndicator] = []
    for e in events:
        mft = e.attributes.get("mft_time")
        logf = e.attributes.get("logfile_time")
        if mft and logf and mft != logf:
            out.append(_ind("timestomp", f"MFT time {mft} disagrees with $LogFile time {logf} for {e.object}",
                            [e.event_id], "high"))
    return out


def detect_sysmon_timestomp(events: list[Event]) -> list[TamperingIndicator]:
    """Flag Sysmon EID 2 file-creation-time changes as possible timestomping.

    Returns
    -------
    list of TamperingIndicator
        One indicator per suspicious ``FILE_TIME_CHANGE`` event.
    """
    out: list[TamperingIndicator] = []
    for e in events:
        if e.event_type != EventType.FILE_TIME_CHANGE:
            continue
        new, prev = e.attributes.get("creation_time"), e.attributes.get("previous_creation_time")
        sev = "medium"
        try:
            if new and prev and parse_ts(new) < parse_ts(prev):
                sev = "high"  # back-dated: the classic timestomp direction
        except ValueError:
            pass
        out.append(_ind("timestomp_sysmon", f"{e.actor} changed creation time of {e.object} from {prev} to {new}",
                        [e.event_id], sev))
    return out


def detect_si_fn_mismatch(events: list[Event], tolerance_s: float = 1.0) -> list[TamperingIndicator]:
    """Flag files whose `$STANDARD_INFORMATION` creation time differs from `$FILE_NAME`.

    Parameters
    ----------
    events : list of Event
        plaso-derived events with an ``ntfs_attribute`` attribute.
    tolerance_s : float
        Allowed difference in seconds before a mismatch is reported.

    Returns
    -------
    list of TamperingIndicator
    """
    created: dict[str, dict[str, Event]] = defaultdict(dict)
    for e in events:
        attr = e.attributes.get("ntfs_attribute")
        if attr and e.action == "created":
            prev = created[e.object].get(attr)
            if prev is None or e.timestamp < prev.timestamp:
                created[e.object][attr] = e
    out: list[TamperingIndicator] = []
    for obj, d in created.items():
        si, fn = d.get("$STANDARD_INFORMATION"), d.get("$FILE_NAME")
        if si and fn and (fn.timestamp - si.timestamp).total_seconds() > tolerance_s:
            out.append(_ind("si_fn_mismatch",
                            f"{obj}: $SI creation {si.timestamp.isoformat()} precedes $FN creation "
                            f"{fn.timestamp.isoformat()} (possible timestomp)", [si.event_id, fn.event_id], "high"))
    return out


def detect_log_clearing(events: list[Event]) -> list[TamperingIndicator]:
    """Report every event-log clearing event as a high-severity indicator."""
    return [_ind("log_cleared", f"{e.actor} cleared {e.object} on {e.attributes.get('host') or '?'}",
                 [e.event_id], "high") for e in events if e.event_type == EventType.LOG_CLEARED]


def detect_audit_tamper(events: list[Event]) -> list[TamperingIndicator]:
    """Report audit-policy changes and audit configuration tampering."""
    out: list[TamperingIndicator] = []
    for e in events:
        if e.event_type == EventType.AUDIT_POLICY_CHANGE:
            out.append(_ind("audit_tamper", f"audit policy changed by {e.actor}", [e.event_id], "medium"))
        elif e.event_type == EventType.REGISTRY_SET and _TAMPER_REG.search(e.object):
            out.append(_ind("audit_tamper", f"{e.actor} modified logging configuration {e.object}",
                            [e.event_id], "high"))
        elif e.event_type == EventType.PROCESS_START and _TAMPER_CMD.search(e.attributes.get("command_line", "")):
            out.append(_ind("audit_tamper", f"logging-tamper command: {e.attributes['command_line'][:160]}",
                            [e.event_id], "high"))
    return out


POWER_WINDOW_S = 300.0


def detect_logging_stopped(events: list[Event], window_s: float = POWER_WINDOW_S) -> list[TamperingIndicator]:
    """Report the Event Log service stopping, crashing or restarting outside a boot or shutdown.

    A clean shutdown logs Security 1100 and a stopped Event Log service, and every boot
    starts it again, so state changes within ``window_s`` of a boot/shutdown marker
    (Security 4608/4609, System 6005/6006/6009/1074) on the same host are normal.
    """
    marks: dict[tuple[str, str], list[float]] = defaultdict(list)
    for e in events:
        if e.event_type == EventType.SYSTEM_POWER:
            marks[(e.attributes.get("host", ""), e.attributes.get("state", ""))].append(e.timestamp.timestamp())

    def near(e: Event, state: str) -> bool:
        t = e.timestamp.timestamp()
        return any(abs(t - m) <= window_s for m in marks.get((e.attributes.get("host", ""), state), ()))

    out: list[TamperingIndicator] = []
    for e in events:
        host = e.attributes.get("host") or "?"
        if e.event_type == EventType.LOGGING_STATE:
            st = e.attributes.get("state", "")
            if st == "crashed":
                out.append(_ind("logging_stopped", f"Event Log service terminated unexpectedly on {host}",
                                [e.event_id], "high"))
            elif st == "stopped" and not near(e, "shutdown"):
                out.append(_ind("logging_stopped", f"Event Log service stopped on {host} outside a shutdown",
                                [e.event_id], "high"))
            elif st == "running" and not near(e, "boot"):
                out.append(_ind("logging_stopped", f"Event Log service (re)started on {host} outside a boot: "
                                "it had stopped or crashed", [e.event_id], "medium"))
            elif st == "shutdown" and not near(e, "shutdown"):
                out.append(_ind("logging_stopped", f"event logging service shut down on {host} outside a "
                                "system shutdown (Security 1100)", [e.event_id], "medium"))
        elif (e.event_type == EventType.PROCESS_START and _WER.search(e.attributes.get("image", ""))
              and _EVENTLOG_HOST.search(e.attributes.get("parent_command_line", ""))):
            out.append(_ind("logging_stopped", f"WerFault reported a crash of the Event Log service host on {host}",
                            [e.event_id], "high"))
    return out


def detect_clock_change(events: list[Event], min_jump_s: float = 300.0) -> list[TamperingIndicator]:
    """Report system clock changes that jump by at least ``min_jump_s`` seconds."""
    out: list[TamperingIndicator] = []
    for e in events:
        if e.event_type != EventType.TIME_CHANGE:
            continue
        try:
            jump = abs((parse_ts(e.attributes["new_time"]) - parse_ts(e.attributes["previous_time"])).total_seconds())
        except (KeyError, ValueError):
            continue
        if jump >= min_jump_s:
            out.append(_ind("clock_change", f"system time changed by {int(jump)}s by {e.actor}", [e.event_id], "medium"))
    return out


def _written_at(e: Event):
    """Channel write time when known (``logged_at``), else the event time."""
    raw = e.attributes.get("logged_at")
    if raw:
        try:
            return parse_ts(raw)
        except ValueError:
            pass
    return e.timestamp


def detect_record_order(events: list[Event], slack_s: float = 60.0) -> list[TamperingIndicator]:
    """Record numbers increase while *write* time goes backwards: clock rollback.

    Uses the channel write time, not the event time: Sysmon reports network
    connections late (EID 3 ``UtcTime`` can precede earlier records by hours),
    which is normal and must not be mistaken for tampering.
    """
    by_channel: dict[tuple[str, str], list[tuple[int, Event]]] = defaultdict(list)
    for e in events:
        rid = e.attributes.get("record_id")
        if rid and rid.isdigit():
            key = (e.attributes.get("host", ""), e.attributes.get("channel", e.source_artifact))
            by_channel[key].append((int(rid), e))
    out: list[TamperingIndicator] = []
    for (host, ch), recs in by_channel.items():
        recs.sort(key=lambda x: x[0])
        latest, latest_t = None, None
        for _, e in recs:
            t = _written_at(e)
            if latest_t is not None and (latest_t - t).total_seconds() > slack_s:
                out.append(_ind("record_order", f"{host}/{ch}: record {e.attributes['record_id']} was written "
                                f"{int((latest_t - t).total_seconds())}s before an earlier-numbered record",
                                [latest.event_id, e.event_id], "medium"))
            if latest_t is None or t > latest_t:
                latest, latest_t = e, t
    return out


def detect_hash_mismatch(events: list[Event]) -> list[TamperingIndicator]:
    """Report events whose stored integrity hash no longer matches their content."""
    return [_ind("hash_mismatch", f"integrity hash mismatch for {e.event_id}", [e.event_id], "high")
            for e in events if e.integrity_hash and not verify_event(e)]


def detect_log_gaps(events: list[Event], gap_threshold_s: float = 1200.0) -> list[TamperingIndicator]:
    """Report silent periods longer than ``gap_threshold_s`` seconds between consecutive events."""
    out: list[TamperingIndicator] = []
    ordered = sorted(events, key=lambda e: e.timestamp)
    for a, b in zip(ordered, ordered[1:]):
        delta = (b.timestamp - a.timestamp).total_seconds()
        if delta > gap_threshold_s:
            out.append(_ind("log_gap", f"no artifacts for {int(delta)}s between {a.event_id} and {b.event_id} (unknown)",
                            [a.event_id, b.event_id], "medium"))
    return out


def scan(graph: ProvenanceGraph, *, gap_threshold_s: float = 1200.0) -> list[TamperingIndicator]:
    """Run every anti-forensics detector over a provenance graph.

    Parameters
    ----------
    graph : ProvenanceGraph
        Graph whose events are scanned.
    gap_threshold_s : float
        Minimum silence, in seconds, reported as a log gap.

    Returns
    -------
    list of TamperingIndicator
        Indicators from all detectors, in detector order.
    """
    events = graph.events
    return (
        detect_timestomp(events)
        + detect_sysmon_timestomp(events)
        + detect_si_fn_mismatch(events)
        + detect_log_clearing(events)
        + detect_audit_tamper(events)
        + detect_logging_stopped(events)
        + detect_clock_change(events)
        + detect_record_order(events)
        + detect_hash_mismatch(events)
        + detect_log_gaps(events, gap_threshold_s)
    )


# indicators that genuinely undermine the evidence inside a chain
CHAIN_PENALISING = {"timestomp", "timestomp_sysmon", "si_fn_mismatch", "hash_mismatch", "record_order", "clock_change"}


def annotate_chain(chain: ProvenanceChain, indicators: list[TamperingIndicator]) -> ProvenanceChain:
    """Attach any indicators whose events fall in the chain."""
    chain_events = set(chain.event_ids)
    chain.tampering_flags = [
        f"{ind.indicator}: {ind.detail}" for ind in indicators if chain_events.intersection(ind.event_ids)
    ]
    return chain
