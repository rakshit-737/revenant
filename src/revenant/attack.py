"""ATT&CK technique tagging + per-case rarity -> event suspicion.

This is the spec's "anomaly scoring to surface unusual events worth graphing".
Two transparent signals, no trained model:

1. **Technique heuristics** -- a Sigma-lite list of generic, well-known
   detection patterns (LOLBins, credential-dumping access masks, persistence
   keys...). Each tag names its ATT&CK technique and tactic so every score is
   explainable. The patterns are generic public detection logic, written
   before looking at benchmark labels; they are *not* tuned per dataset.
2. **Rarity** -- how unusual a parent->child image pair is *within this case*
   (``1 / (1 + log(1 + count))``); first-seen pairs get 1.0.

``suspicion = 1 - (1 - technique_weight) * (1 - 0.35 * rarity)``
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from .entities import image_key, split_process_ref
from .models import Event, EventType

TACTICS = {
    "TA0001": "initial-access", "TA0002": "execution", "TA0003": "persistence",
    "TA0004": "privilege-escalation", "TA0005": "defense-evasion", "TA0006": "credential-access",
    "TA0007": "discovery", "TA0008": "lateral-movement", "TA0009": "collection",
    "TA0011": "command-and-control", "TA0010": "exfiltration", "TA0040": "impact",
}


@dataclass(frozen=True)
class Heuristic:
    technique: str
    name: str
    tactic: str
    weight: float
    match: Callable[[Event], bool]


def _img(ev: Event) -> str:
    img = ev.attributes.get("image") or ""
    if not img:
        parts = split_process_ref(ev.object if ev.event_type == EventType.PROCESS_START else ev.actor)
        img = parts[1] if parts else ""
    return image_key(img)


def _cmd(ev: Event) -> str:
    return (ev.attributes.get("command_line") or "").lower()


def _start(images: tuple[str, ...], pattern: str | None = None) -> Callable[[Event], bool]:
    rx = re.compile(pattern, re.IGNORECASE) if pattern else None

    def f(ev: Event) -> bool:
        if ev.event_type != EventType.PROCESS_START or _img(ev) not in images:
            return False
        return True if rx is None else bool(rx.search(_cmd(ev)))

    return f


def _cmd_any(pattern: str) -> Callable[[Event], bool]:
    rx = re.compile(pattern, re.IGNORECASE)
    return lambda ev: ev.event_type == EventType.PROCESS_START and bool(rx.search(_cmd(ev)))


def _reg(pattern: str) -> Callable[[Event], bool]:
    rx = re.compile(pattern, re.IGNORECASE)
    return lambda ev: ev.event_type == EventType.REGISTRY_SET and bool(rx.search(ev.object.replace("\\", "/")))


def _type(t: EventType) -> Callable[[Event], bool]:
    return lambda ev: ev.event_type == t


def _lsass_access(ev: Event) -> bool:
    if ev.event_type != EventType.PROCESS_ACCESS:
        return False
    if image_key(ev.attributes.get("target_image", "")) != "lsass.exe":
        return False
    return ev.attributes.get("granted_access", "") in {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff", "0x1f3fff", "0x1f1fff", "0x40"}


def _remote_thread(ev: Event) -> bool:
    return ev.event_type == EventType.REMOTE_THREAD


def _script(pattern: str) -> Callable[[Event], bool]:
    rx = re.compile(pattern, re.IGNORECASE)
    return lambda ev: ev.event_type == EventType.SCRIPT_BLOCK and bool(rx.search(ev.attributes.get("script", "")))


def _logon_type(t: str, extra: Callable[[Event], bool] | None = None) -> Callable[[Event], bool]:
    return lambda ev: (ev.event_type == EventType.LOGON and ev.attributes.get("logon_type") == t
                       and (extra is None or extra(ev)))


def _parent_child(parents: tuple[str, ...], children: tuple[str, ...]) -> Callable[[Event], bool]:
    def f(ev: Event) -> bool:
        if ev.event_type != EventType.PROCESS_START:
            return False
        parent = image_key(ev.attributes.get("parent_image") or (split_process_ref(ev.actor) or ("", ""))[1])
        return parent in parents and _img(ev) in children

    return f


_SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
_OFFICE = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe")

HEURISTICS: list[Heuristic] = [
    # execution
    Heuristic("T1059.001", "PowerShell with encoded/hidden/download cradle", "TA0002", 0.7,
              _start(("powershell.exe", "pwsh.exe"), r"-e(nc(odedcommand)?)?\s|-w(indowstyle)?\s+h|iex|invoke-expression|downloadstring|frombase64string|-nop")),
    Heuristic("T1059.001", "Suspicious PowerShell script block", "TA0002", 0.6,
              _script(r"invoke-mimikatz|frombase64string|downloadstring|virtualalloc|invoke-shellcode|-bxor|reflection\.assembly|amsiutils")),
    Heuristic("T1059.003", "cmd spawned by Office/script host", "TA0002", 0.6, _parent_child(_OFFICE + ("wscript.exe", "cscript.exe", "mshta.exe"), ("cmd.exe", "powershell.exe"))),
    Heuristic("T1047", "WMI process creation", "TA0002", 0.55, _parent_child(("wmiprvse.exe",), _SHELLS + ("rundll32.exe",))),
    Heuristic("T1047", "wmic process call create", "TA0002", 0.6, _start(("wmic.exe",), r"process\s+call\s+create|/node:")),
    Heuristic("T1053.005", "Scheduled task created", "TA0003", 0.6, _start(("schtasks.exe",), r"/create|/change")),
    Heuristic("T1053.005", "Scheduled task registered (4698)", "TA0003", 0.55, _type(EventType.SCHEDULED_TASK)),
    Heuristic("T1569.002", "PsExec service binary", "TA0002", 0.7, _start(("psexesvc.exe",))),
    Heuristic("T1569.002", "Service created/started with sc", "TA0002", 0.5, _start(("sc.exe",), r"(create|start|config)")),
    # persistence / privilege escalation
    Heuristic("T1547.001", "Run/RunOnce key modification", "TA0003", 0.65, _reg(r"/currentversion/run(once)?(/|$)")),
    Heuristic("T1543.003", "Service installed", "TA0003", 0.55, _type(EventType.SERVICE_INSTALL)),
    Heuristic("T1546.003", "WMI event subscription", "TA0003", 0.7, _type(EventType.WMI_EVENT)),
    Heuristic("T1037.001", "Logon script (UserInitMprLogonScript)", "TA0003", 0.7, _reg(r"userinitmprlogonscript")),
    Heuristic("T1136.001", "Local account created/changed", "TA0003", 0.5, lambda ev: ev.event_type == EventType.ACCOUNT_CHANGE and ev.action.endswith("4720")),
    Heuristic("T1136.001", "net user /add", "TA0003", 0.6, _start(("net.exe", "net1.exe"), r"user\s+\S+\s+\S*\s*/add")),
    Heuristic("T1548.002", "UAC bypass via auto-elevating binary", "TA0004", 0.7, _parent_child(("fodhelper.exe", "computerdefaults.exe", "eventvwr.exe", "sdclt.exe", "cmstp.exe"), _SHELLS)),
    Heuristic("T1548.002", "UAC bypass registry hijack", "TA0004", 0.7, _reg(r"ms-settings/shell/open/command|mscfile/shell/open/command|exefile/shell/runas")),
    # defense evasion
    Heuristic("T1218.005", "mshta execution", "TA0005", 0.65, _start(("mshta.exe",))),
    Heuristic("T1218.010", "regsvr32 scriptlet / remote", "TA0005", 0.7, _start(("regsvr32.exe",), r"/i:|scrobj|http")),
    Heuristic("T1218.011", "rundll32 script / MiniDump", "TA0005", 0.6, _start(("rundll32.exe",), r"javascript:|comsvcs|minidump|url\.dll|shell32\.dll,control_rundll")),
    Heuristic("T1218.003", "CMSTP execution", "TA0005", 0.7, _start(("cmstp.exe",))),
    Heuristic("T1218.004", "InstallUtil execution", "TA0005", 0.65, _start(("installutil.exe",))),
    Heuristic("T1218.001", "Compiled HTML help", "TA0005", 0.6, _start(("hh.exe",))),
    Heuristic("T1218.002", "Control panel item", "TA0005", 0.45, _start(("control.exe",), r"\.cpl")),
    Heuristic("T1218", "Mavinject / register-cimprovider proxy exec", "TA0005", 0.7, _start(("mavinject.exe", "register-cimprovider.exe", "wuauclt.exe"), r"inject|/dll|-path|/updatedeploymentprovider")),
    Heuristic("T1127.001", "MSBuild execution", "TA0005", 0.6, _start(("msbuild.exe",))),
    Heuristic("T1197", "BITS job", "TA0005", 0.6, _start(("bitsadmin.exe",), r"/transfer|/addfile|/create")),
    Heuristic("T1105", "certutil / download utility", "TA0011", 0.6, _cmd_any(r"urlcache|verifyctl|-decode|invoke-webrequest|start-bitstransfer|wget |curl ")),
    Heuristic("T1070.001", "Event log cleared", "TA0005", 0.8, _type(EventType.LOG_CLEARED)),
    Heuristic("T1070.001", "wevtutil clear/relocate log", "TA0005", 0.75, _start(("wevtutil.exe",), r"\s(cl|clear-log|sl|set-log)\s")),
    Heuristic("T1562.002", "Event logging disabled via registry", "TA0005", 0.8, _reg(r"services/eventlog/start$|control/minint|services/eventlog/.*/(file|maxsize|retention)$")),
    Heuristic("T1562.002", "Audit policy changed", "TA0005", 0.7, _type(EventType.AUDIT_POLICY_CHANGE)),
    Heuristic("T1562.002", "auditpol / stop eventlog", "TA0005", 0.7, _cmd_any(r"auditpol\s+/(set|clear|remove)|stop-service\s+.*eventlog|sc\s+(stop|config)\s+eventlog|net\s+stop\s+eventlog")),
    Heuristic("T1562.004", "Firewall modified", "TA0005", 0.6, _start(("netsh.exe",), r"firewall|advfirewall")),
    Heuristic("T1112", "Security-relevant registry modification", "TA0005", 0.6, _reg(r"wdigest/uselogoncredential|lsa/(disablerestrictedadmin|runasppl|lmcompatibilitylevel)|processcreationincludecmdline_enabled|terminal server/fdenytsconnections|restrictsendingntlmtraffic|ntlmminclientsec")),
    Heuristic("T1070.006", "Timestomp (file creation time changed)", "TA0005", 0.5, _type(EventType.FILE_TIME_CHANGE)),
    Heuristic("T1055", "CreateRemoteThread injection", "TA0005", 0.7, _remote_thread),
    Heuristic("T1574.001", "DLL written to system/service dir", "TA0005", 0.45,
              lambda ev: ev.event_type == EventType.FILE_WRITE and bool(re.search(r"(system32|syswow64|/windows/)[^ ]*\.dll$", ev.object.lower().replace("\\", "/")))),
    # credential access
    Heuristic("T1003.001", "LSASS memory access", "TA0006", 0.8, _lsass_access),
    Heuristic("T1003.001", "LSASS dump utility", "TA0006", 0.85, _cmd_any(r"lsass|comsvcs.*minidump|procdump.*-ma|sekurlsa")),
    Heuristic("T1003.002", "SAM/SECURITY hive copy", "TA0006", 0.8, _cmd_any(r"(reg(\.exe)?\s+save\s+hklm\\(sam|security|system))|esentutl.*(sam|ntds)|config[/\\]sam")),
    Heuristic("T1003.003", "NTDS.dit access", "TA0006", 0.85, _cmd_any(r"ntdsutil|ntds\.dit|vssadmin.*create\s+shadow|shadowcopy|diskshadow")),
    Heuristic("T1003.006", "DCSync-like replication request", "TA0006", 0.6, _script(r"dcsync|lsadump::dcsync|drsuapi")),
    Heuristic("T1056.002", "Credential prompt (GUI input capture)", "TA0006", 0.6, _script(r"promptforcredential|get-credential")),
    Heuristic("T1555.004", "Windows vault access", "TA0006", 0.6, _script(r"passwordvault|vaultcmd|windows\.security\.credentials")),
    Heuristic("T1550.002", "Pass-the-hash style logon (type 9 / NewCredentials)", "TA0008", 0.65, _logon_type("9")),
    # discovery
    Heuristic("T1087", "Account/group discovery", "TA0007", 0.35, _start(("net.exe", "net1.exe"), r"\b(user|group|localgroup)\b(?!.*/add)")),
    Heuristic("T1082", "System information discovery", "TA0007", 0.3, _start(("systeminfo.exe", "whoami.exe", "hostname.exe", "ipconfig.exe", "nltest.exe", "quser.exe", "qwinsta.exe"))),
    Heuristic("T1069", "LDAP/AD enumeration script", "TA0007", 0.5, _script(r"get-domain|powerview|directorysearcher|ldap://")),
    # lateral movement
    Heuristic("T1021.006", "WinRM / PowerShell remoting host", "TA0008", 0.6, _start(("wsmprovhost.exe",))),
    Heuristic("T1021.003", "DCOM spawned process", "TA0008", 0.55, _parent_child(("mmc.exe", "excel.exe", "explorer.exe", "svchost.exe"), ("cmd.exe", "powershell.exe", "rundll32.exe", "mshta.exe")) ),
    Heuristic("T1021.001", "RDP logon (type 10)", "TA0008", 0.4, _logon_type("10")),
    Heuristic("T1021.002", "Network logon with admin share tooling", "TA0008", 0.35, _logon_type("3", lambda ev: ev.attributes.get("auth_package", "").lower() == "ntlm")),
    # collection / C2
    Heuristic("T1123", "Audio capture device access", "TA0009", 0.5, _reg(r"capabilityaccessmanager/consentstore/microphone")),
    Heuristic("T1071.001", "Scripting host network connection", "TA0011", 0.45,
              lambda ev: ev.event_type == EventType.NETWORK_CONNECT and _img(ev) in ("powershell.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "msbuild.exe", "installutil.exe")),
]


@dataclass
class EventTags:
    techniques: list[tuple[str, str, str]]  # (technique, tactic, name)
    technique_weight: float
    rarity: float
    suspicion: float


def _pair(ev: Event) -> str | None:
    if ev.event_type != EventType.PROCESS_START:
        return None
    parent = split_process_ref(ev.actor)
    return f"{image_key(parent[1]) if parent else ''}>{_img(ev)}"


def score_events(events: list[Event]) -> dict[str, EventTags]:
    pairs = Counter(p for p in (_pair(e) for e in events) if p)
    out: dict[str, EventTags] = {}
    for ev in events:
        hits = [(h.technique, h.tactic, h.name, h.weight) for h in HEURISTICS if h.match(ev)]
        tw = max((w for *_, w in hits), default=0.0)
        p = _pair(ev)
        rarity = 1.0 / (1.0 + math.log1p(pairs[p] - 1)) if p else 0.0
        susp = 1.0 - (1.0 - tw) * (1.0 - 0.35 * rarity)
        out[ev.event_id] = EventTags([(t, ta, n) for t, ta, n, _ in hits], tw, round(rarity, 4), round(susp, 4))
    return out


def technique_parent(t: str) -> str:
    return t.split(".")[0]
