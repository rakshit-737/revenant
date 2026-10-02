"""Windows event-log mapper: one flattened event record -> one normalized Event.

The input is the *flattened* shape shared by every Windows source REVENANT
reads: ``EventID``, ``Channel``, ``Hostname``/``Computer`` plus the EventData
fields at top level. That is exactly what OTRF Security-Datasets ship (JSON
lines exported by Logstash/NXLog), and what `revenant.parsers.evtx`
produces from raw ``.evtx`` files via python-evtx.

Coverage (deliberately the evidence types the causal rules consume):

========================  ===================================================
Sysmon                    1 2 3 5 8 9 10 11 12 13 14 15 17 18 19 20 21 22 23 26
                          (7 image-load only with ``include_noisy``)
Security                  1102 4616 4624 4625 4634 4647 4657 4688 4689 4697
                          4698 4719 4720 4722 4724 4728 4732 4738 4756 5156
System                    104 7045
PowerShell/Operational    4104
========================  ===================================================

Anything else returns ``None`` (not ingested); callers count those so the
coverage is reported, never hidden.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..entities import norm_host, norm_pid, norm_user, process_ref
from ..integrity import finalize_event
from ..models import Event, EventType, SourceReliability

MAX_ATTR = 2048

SYSMON = "sysmon"
SECURITY = "security"
SYSTEM = "system"
POWERSHELL = "powershell"

RELIABILITY = {
    # Admiralty-style: Security audit log is written by LSA/kernel (A);
    # Sysmon is a well-tested driver but configurable/evadable (B);
    # PowerShell script-block logging can be disabled by the attacker (C).
    SECURITY: SourceReliability.A,
    SYSMON: SourceReliability.B,
    SYSTEM: SourceReliability.B,
    POWERSHELL: SourceReliability.C,
}


def channel_kind(rec: dict[str, Any]) -> str | None:
    """Return the source kind of a Windows event record, or None."""
    ch = str(rec.get("Channel") or rec.get("SourceName") or "").lower()
    if "sysmon" in ch:
        return SYSMON
    if ch == "security" or "security-auditing" in ch:
        return SECURITY
    if ch == "system":
        return SYSTEM
    if "powershell" in ch:
        return POWERSHELL
    return None


def _s(v: Any) -> str:
    if v is None:
        return ""
    s = str(v)
    return s if len(s) <= MAX_ATTR else s[:MAX_ATTR] + "...[truncated]"


def _logon_id(v: Any) -> str:
    if v in (None, "", "-"):
        return ""
    try:
        s = str(v).strip()
        return hex(int(s, 16) if s.lower().startswith("0x") else int(s))
    except ValueError:
        return str(v).lower()


def _guid(v: Any) -> str:
    return str(v).strip("{}").lower() if v else ""


def _get(rec: dict[str, Any], *names: str) -> Any:
    for n in names:
        v = rec.get(n)
        if v not in (None, ""):
            return v
    return None


def _proc(rec: dict[str, Any], pid_field: str, image_field: str) -> str:
    # NXLog exports occasionally spell EventData ``ProcessId`` as ``ProcessID``
    # (never fall back to ``ExecutionProcessID``: that is the *logging* process)
    alt = pid_field[:-2] + "ID" if pid_field.endswith("Id") else pid_field
    return process_ref(_get(rec, pid_field, alt), rec.get(image_field))


def map_windows_event(
    rec: dict[str, Any], timestamp: datetime, *, include_noisy: bool = False
) -> Event | None:
    """Map one flattened Windows event to an `Event` (or ``None``)."""
    kind = channel_kind(rec)
    if kind is None:
        return None
    try:
        eid = int(rec.get("EventID", -1))
    except (TypeError, ValueError):
        return None
    host = norm_host(_get(rec, "Hostname", "Computer", "host_name"))
    attrs: dict[str, str] = {"host": host, "channel": kind, "event_id": str(eid)}
    rid = _get(rec, "RecordNumber", "EventRecordID")
    if rid is not None:
        attrs["record_id"] = _s(rid)
    # when the record was *written* to its channel (collector clock). Event
    # times such as Sysmon 3 UtcTime can legitimately run backwards against
    # record order; write times cannot, unless the clock was manipulated.
    logged = _get(rec, "TimeCreated", "EventTime")
    if logged is not None:
        attrs["logged_at"] = _s(logged)

    mapped = _map_sysmon(rec, eid, attrs, include_noisy) if kind == SYSMON else None
    if kind == SECURITY:
        mapped = _map_security(rec, eid, attrs)
    elif kind == SYSTEM:
        mapped = _map_system(rec, eid, attrs)
    elif kind == POWERSHELL:
        mapped = _map_powershell(rec, eid, attrs)
    if mapped is None:
        return None
    etype, actor, action, obj = mapped
    ev = Event(
        event_id="pending",
        timestamp=timestamp,
        event_type=etype,
        actor=actor or "unknown",
        action=action,
        object=obj or "unknown",
        source_artifact=kind,
        source_reliability=RELIABILITY[kind],
        attributes={k: v for k, v in attrs.items() if v not in (None, "")},
    )
    return finalize_event(ev)


Mapped = tuple[EventType, str, str, str]


def _map_sysmon(rec: dict[str, Any], eid: int, a: dict[str, str], noisy: bool) -> Mapped | None:
    proc = _proc(rec, "ProcessId", "Image")
    guid = _guid(_get(rec, "ProcessGuid", "ProcessGUID"))
    if rec.get("User"):
        a["user"] = norm_user(rec.get("User"))
    if eid == 1:
        a.update(
            image=_s(rec.get("Image")),
            parent_image=_s(rec.get("ParentImage")),
            command_line=_s(rec.get("CommandLine")),
            parent_command_line=_s(rec.get("ParentCommandLine")),
            logon_id=_logon_id(rec.get("LogonId")),
            integrity_level=_s(rec.get("IntegrityLevel")),
            hashes=_s(rec.get("Hashes")),
            actor_guid=_guid(_get(rec, "ParentProcessGuid", "ParentProcessGUID")),
            object_guid=guid,
        )
        return (EventType.PROCESS_START, _proc(rec, "ParentProcessId", "ParentImage"), "spawned", proc)
    a["actor_guid"] = guid
    if eid == 2:
        a.update(
            creation_time=_s(rec.get("CreationUtcTime")),
            previous_creation_time=_s(rec.get("PreviousCreationUtcTime")),
        )
        return (EventType.FILE_TIME_CHANGE, proc, "changed_creation_time", f"file:{rec.get('TargetFilename', '?')}")
    if eid == 3:
        a.update(
            src_ip=_s(rec.get("SourceIp")),
            dst_host=_s(rec.get("DestinationHostname")),
            protocol=_s(rec.get("Protocol")),
            initiated=_s(rec.get("Initiated")),
        )
        return (
            EventType.NETWORK_CONNECT,
            proc,
            "connected",
            f"ip:{rec.get('DestinationIp', '?')}:{rec.get('DestinationPort', '?')}",
        )
    if eid == 5:
        return (EventType.PROCESS_STOP, proc, "terminated", proc)
    if eid == 7:
        if not noisy:
            return None
        return (EventType.OTHER, proc, "loaded", f"file:{rec.get('ImageLoaded', '?')}")
    if eid in (8, 10):
        a["actor_guid"] = _guid(_get(rec, "SourceProcessGuid", "SourceProcessGUID"))
        a["object_guid"] = _guid(_get(rec, "TargetProcessGuid", "TargetProcessGUID"))
        src = _proc(rec, "SourceProcessId", "SourceImage")
        dst = _proc(rec, "TargetProcessId", "TargetImage")
        a["target_image"] = _s(rec.get("TargetImage"))
        if eid == 8:
            a["start_function"] = _s(rec.get("StartFunction"))
            return (EventType.REMOTE_THREAD, src, "injected_thread", dst)
        a["granted_access"] = _s(rec.get("GrantedAccess")).lower()
        return (EventType.PROCESS_ACCESS, src, "opened_handle", dst)
    if eid == 9:
        return (EventType.FILE_READ, proc, "raw_read", f"file:{rec.get('Device', '?')}")
    if eid in (11, 15):
        return (EventType.FILE_WRITE, proc, "wrote", f"file:{rec.get('TargetFilename', '?')}")
    if eid in (12, 13, 14):
        a.update(reg_op=_s(rec.get("EventType")), details=_s(rec.get("Details")))
        return (EventType.REGISTRY_SET, proc, "set", f"registry:{rec.get('TargetObject', '?')}")
    if eid in (17, 18):
        return (EventType.PIPE, proc, "pipe", f"pipe:{rec.get('PipeName', '?')}")
    if eid in (19, 20, 21):
        a.update(
            wmi_op=_s(rec.get("Operation")),
            destination=_s(rec.get("Destination")),
            query=_s(rec.get("Query")),
        )
        name = _get(rec, "Name", "Consumer", "Filter") or "?"
        return (EventType.WMI_EVENT, f"user:{norm_user(rec.get('User')) or '?'}", "registered", f"wmi:{name}")
    if eid == 22:
        a["query_results"] = _s(rec.get("QueryResults"))
        return (EventType.DNS_QUERY, proc, "queried", f"dns:{rec.get('QueryName', '?')}")
    if eid in (23, 26):
        return (EventType.FILE_DELETE, proc, "deleted", f"file:{rec.get('TargetFilename', '?')}")
    return None


_ACCOUNT_EIDS = {4720, 4722, 4724, 4728, 4732, 4738, 4756}


def _map_security(rec: dict[str, Any], eid: int, a: dict[str, str]) -> Mapped | None:
    if eid in (4624, 4625):
        user = norm_user(rec.get("TargetUserName"))
        a.update(
            user=user,
            logon_id=_logon_id(rec.get("TargetLogonId")),
            logon_type=_s(rec.get("LogonType")),
            src_ip=_s(rec.get("IpAddress")),
            workstation=_s(rec.get("WorkstationName")),
            auth_package=_s(rec.get("AuthenticationPackageName")),
            logon_process=_s(rec.get("LogonProcessName")).strip(),
        )
        et = EventType.LOGON if eid == 4624 else EventType.LOGON_FAILED
        action = "authenticated" if eid == 4624 else "failed_logon"
        return (et, f"user:{user or '?'}", action, f"host:{a['host'] or '?'}")
    if eid in (4634, 4647):
        user = norm_user(rec.get("TargetUserName"))
        a.update(user=user, logon_id=_logon_id(rec.get("TargetLogonId")))
        return (EventType.LOGOFF, f"user:{user or '?'}", "logged_off", f"host:{a['host'] or '?'}")
    if eid == 4688:
        a.update(
            image=_s(rec.get("NewProcessName")),
            parent_image=_s(rec.get("ParentProcessName")),
            command_line=_s(rec.get("CommandLine")),
            user=norm_user(rec.get("SubjectUserName")),
            logon_id=_logon_id(rec.get("SubjectLogonId")),
        )
        return (
            EventType.PROCESS_START,
            process_ref(rec.get("ProcessId"), rec.get("ParentProcessName")),
            "spawned",
            process_ref(rec.get("NewProcessId"), rec.get("NewProcessName")),
        )
    if eid == 4689:
        p = process_ref(rec.get("ProcessId"), rec.get("ProcessName"))
        return (EventType.PROCESS_STOP, p, "terminated", p)
    if eid == 4657:
        p = process_ref(rec.get("ProcessId"), rec.get("ProcessName"))
        a["details"] = _s(rec.get("NewValue"))
        key = f"{rec.get('ObjectName', '?')}\\{rec.get('ObjectValueName', '')}"
        return (EventType.REGISTRY_SET, p, "set", f"registry:{key}")
    if eid == 4697:
        a["service_file"] = _s(rec.get("ServiceFileName"))
        return (EventType.SERVICE_INSTALL, f"user:{norm_user(rec.get('SubjectUserName')) or '?'}",
                "installed_service", f"service:{rec.get('ServiceName', '?')}")
    if eid == 4698:
        a["task_content"] = _s(rec.get("TaskContent"))
        return (EventType.SCHEDULED_TASK, f"user:{norm_user(rec.get('SubjectUserName')) or '?'}",
                "created_task", f"task:{rec.get('TaskName', '?')}")
    if eid in _ACCOUNT_EIDS:
        return (EventType.ACCOUNT_CHANGE, f"user:{norm_user(rec.get('SubjectUserName')) or '?'}",
                f"account_change_{eid}", f"account:{norm_user(rec.get('TargetUserName')) or '?'}")
    if eid == 4719:
        a.update(category=_s(rec.get("CategoryId")), subcategory=_s(rec.get("SubcategoryGuid")),
                 changes=_s(rec.get("AuditPolicyChanges")))
        return (EventType.AUDIT_POLICY_CHANGE, f"user:{norm_user(rec.get('SubjectUserName')) or '?'}",
                "changed_audit_policy", "audit_policy")
    if eid == 1102:
        return (EventType.LOG_CLEARED, f"user:{norm_user(_get(rec, 'SubjectUserName', 'UserName')) or '?'}",
                "cleared_log", "log:security")
    if eid == 4616:
        a.update(previous_time=_s(rec.get("PreviousTime")), new_time=_s(rec.get("NewTime")))
        return (EventType.TIME_CHANGE, process_ref(rec.get("ProcessId"), rec.get("ProcessName")),
                "changed_system_time", "clock")
    if eid == 5156:
        direction = str(rec.get("Direction", ""))
        if "14593" not in direction and "outbound" not in direction.lower():
            return None  # inbound accepts are overwhelmingly background noise
        p = process_ref(_get(rec, "ProcessID", "ProcessId"), rec.get("Application"))
        a["src_ip"] = _s(rec.get("SourceAddress"))
        return (EventType.NETWORK_CONNECT, p, "connected",
                f"ip:{rec.get('DestAddress', '?')}:{rec.get('DestPort', '?')}")
    return None


def _map_system(rec: dict[str, Any], eid: int, a: dict[str, str]) -> Mapped | None:
    if eid == 7045:
        a.update(service_file=_s(rec.get("ImagePath")), account=_s(rec.get("AccountName")))
        return (EventType.SERVICE_INSTALL, "system:scm", "installed_service",
                f"service:{rec.get('ServiceName', '?')}")
    if eid == 104:
        log = _get(rec, "Channel_", "BackupPath", "LogName") or "system"
        return (EventType.LOG_CLEARED, f"user:{norm_user(_get(rec, 'SubjectUserName', 'UserName')) or '?'}",
                "cleared_log", f"log:{str(log).lower()}")
    return None


def _map_powershell(rec: dict[str, Any], eid: int, a: dict[str, str]) -> Mapped | None:
    if eid != 4104:
        return None
    pid = norm_pid(_get(rec, "ExecutionProcessID", "ProcessID"))
    a.update(
        script_block_id=_s(rec.get("ScriptBlockId")),
        script=_s(rec.get("ScriptBlockText")),
        path=_s(rec.get("Path")),
    )
    return (EventType.SCRIPT_BLOCK, f"process:{pid or '?'}:", "ran_script",
            f"script:{a['script_block_id'] or '?'}")
