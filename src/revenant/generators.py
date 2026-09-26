"""Synthetic forensic data generators.

Deterministic, lab-only scenarios so REVENANT can be demoed and tested without
touching real personal data or real malware. Records are raw (pre-normalize)
dicts in the shapes the normalizer understands. No real exploit code is
generated — these are benign, synthetic artifact traces.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

_BASE = datetime(2024, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


def _t(offset_s: int) -> str:
    return (_BASE + timedelta(seconds=offset_s)).isoformat()


Record = tuple[str, dict[str, Any]]


def intrusion_scenario() -> list[Record]:
    """Phishing doc -> macro -> PowerShell -> persistence -> DNS -> C2 beacon."""
    return [
        # user logs on (seen in auth log)
        ("auth", {"time": _t(0), "event": "logon", "user": "alice", "host": "WS01",
                  "src_ip": "10.0.0.9", "source": "auth", "reliability": "B"}),
        # winword launched under alice's session
        ("sysmon", {"EventID": 1, "UtcTime": _t(30), "ProcessId": "200",
                    "Image": "C:/Program Files/winword.exe", "ParentProcessId": "100",
                    "ParentImage": "C:/Windows/explorer.exe", "User": "alice"}),
        # macro spawns powershell
        ("sysmon", {"EventID": 1, "UtcTime": _t(60), "ProcessId": "300",
                    "Image": "C:/Windows/System32/powershell.exe", "ParentProcessId": "200",
                    "ParentImage": "C:/Program Files/winword.exe", "User": "alice"}),
        # powershell drops a dll
        ("sysmon", {"EventID": 11, "UtcTime": _t(75), "ProcessId": "300",
                    "Image": "C:/Windows/System32/powershell.exe",
                    "TargetFilename": "C:/Users/alice/AppData/Roaming/beacon.dll",
                    "Hashes": "SHA256=deadbeef"}),
        # persistence via Run key
        ("sysmon", {"EventID": 13, "UtcTime": _t(90), "ProcessId": "300",
                    "Image": "C:/Windows/System32/powershell.exe",
                    "TargetObject": "HKCU/Software/Microsoft/Windows/CurrentVersion/Run/updater"}),
        # dns lookup for C2
        ("sysmon", {"EventID": 22, "UtcTime": _t(105), "ProcessId": "300",
                    "Image": "C:/Windows/System32/powershell.exe",
                    "QueryName": "c2.example-lab.test"}),
        # C2 beacon network connect
        ("sysmon", {"EventID": 3, "UtcTime": _t(120), "ProcessId": "300",
                    "Image": "C:/Windows/System32/powershell.exe",
                    "DestinationIp": "203.0.113.5", "DestinationPort": "443"}),
    ]


def corroboration_scenario() -> list[Record]:
    """Same logon observed by two independent sources -> confidence boost."""
    return [
        ("auth", {"time": _t(0), "event": "logon", "user": "bob", "host": "WS02",
                  "src_ip": "10.0.0.4", "source": "auth", "reliability": "B"}),
        ("auth", {"time": _t(1), "event": "logon", "user": "bob", "host": "WS02",
                  "src_ip": "10.0.0.4", "source": "security_eid_4624", "reliability": "A"}),
        ("sysmon", {"EventID": 1, "UtcTime": _t(5), "ProcessId": "410",
                    "Image": "C:/Windows/System32/cmd.exe", "ParentProcessId": "1",
                    "ParentImage": "C:/Windows/System32/services.exe", "User": "bob"}),
    ]


def timestomp_scenario() -> list[Record]:
    """A dropped file whose MFT and $LogFile timestamps disagree (anti-forensics)."""
    return [
        ("sysmon", {"EventID": 1, "UtcTime": _t(0), "ProcessId": "500",
                    "Image": "C:/Windows/System32/powershell.exe", "ParentProcessId": "1",
                    "ParentImage": "C:/Windows/System32/services.exe", "User": "eve"}),
        ("plaso", {"timestamp": _t(20), "event_type": "file_write", "action": "wrote",
                   "actor": "process:500:C:/Windows/System32/powershell.exe",
                   "object": "file:C:/Windows/Temp/evil.exe", "source": "plaso",
                   "reliability": "C",
                   "attributes": {"mft_time": _t(20), "logfile_time": _t(99999)}}),
    ]


def big_timeline(n_processes: int = 50) -> list[Record]:
    """Scale-test generator: a fan-out of benign process spawns and file writes."""
    records: list[Record] = []
    for i in range(n_processes):
        pid = str(1000 + i)
        records.append(
            ("sysmon", {"EventID": 1, "UtcTime": _t(i * 2), "ProcessId": pid,
                        "Image": f"C:/tmp/proc_{i}.exe", "ParentProcessId": "1",
                        "ParentImage": "C:/Windows/System32/services.exe", "User": "svc"})
        )
        records.append(
            ("sysmon", {"EventID": 11, "UtcTime": _t(i * 2 + 1), "ProcessId": pid,
                        "Image": f"C:/tmp/proc_{i}.exe",
                        "TargetFilename": f"C:/tmp/out_{i}.log"})
        )
    return records


SCENARIOS = {
    "intrusion": intrusion_scenario,
    "corroboration": corroboration_scenario,
    "timestomp": timestomp_scenario,
    "scale": big_timeline,
}
