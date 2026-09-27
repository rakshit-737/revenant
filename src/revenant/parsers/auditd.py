"""Linux auditd connector (``/var/log/audit/audit.log``).

One syscall is spread over several records that share an event serial
(``msg=audit(<epoch>:<serial>)``): ``SYSCALL`` (who / which call / result),
``EXECVE`` (argv), ``CWD``, ``PATH`` (one per touched inode) and ``SOCKADDR``
(hex-encoded address). Records are grouped by serial and mapped:

=============================  ==========================================
syscall                        normalized event
=============================  ==========================================
execve / execveat (success)    ``process_start`` (parent -> child image)
open / openat / creat (write)  ``file_write`` (O_WRONLY/O_RDWR/O_CREAT/
                               O_TRUNC, or a ``CREATE`` PATH item)
open / openat (read-only)      ``file_read`` (only when a rule key asked)
unlink* / rename*              ``file_delete`` (the removed/renamed name)
connect (AF_INET / AF_INET6)   ``network_connect``
=============================  ==========================================

auditd reports the parent only as ``ppid``. The parent's *image* is recovered
from the most recent ``execve`` of that PID earlier in the log (auditd sees
every exec after the rules load); processes that exec'd before auditing began
keep an empty image, so the engine's ``host|pid|image`` keys cannot silently
link them to an unrelated process that reused the PID.

The source is rated B (kernel audit subsystem; complete for what the rules
cover, but the rules are configurable by root).
"""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from ..entities import process_ref
from ..integrity import finalize_event
from ..models import Event, EventType, SourceReliability
from .otrf import LoadStats

_HDR = re.compile(r"type=(?P<type>\S+) msg=audit\((?P<ts>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s*(?P<body>.*)$")
_KV = re.compile(r'([A-Za-z0-9_]+)=("(?:[^"\\]|\\.)*"|\S+)')

# x86_64 / aarch64 (generic) syscall numbers for raw (non -i) logs
_SYSCALLS_X86_64 = {
    "59": "execve", "322": "execveat", "2": "open", "257": "openat", "85": "creat", "437": "openat2",
    "87": "unlink", "263": "unlinkat", "82": "rename", "264": "renameat", "316": "renameat2", "42": "connect",
}
_SYSCALLS_AARCH64 = {
    "221": "execve", "281": "execveat", "56": "openat", "437": "openat2", "35": "unlinkat",
    "38": "renameat", "276": "renameat2", "203": "connect",
}
_ARCH_AARCH64 = {"c00000b7", "aarch64"}
_EXEC = {"execve", "execveat"}
_OPEN = {"open", "openat", "creat", "openat2"}
_DELETE = {"unlink", "unlinkat", "rename", "renameat", "renameat2"}
_O_WRITE_MASK = 0x1 | 0x2 | 0x40 | 0x200  # O_WRONLY | O_RDWR | O_CREAT | O_TRUNC


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _decode_hex(v: str) -> str:
    """auditd hex-encodes strings containing spaces/quotes/non-ASCII."""
    if v.startswith('"') or v in ("(null)", "?") or len(v) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", v):
        return _unquote(v)
    try:
        return bytes.fromhex(v).decode("utf-8", errors="replace").replace("\x00", " ").strip()
    except ValueError:
        return v


def parse_line(line: str) -> tuple[str, float, str, dict[str, str]] | None:
    m = _HDR.search(line)
    if not m:
        return None
    body = m["body"].split("\x1d", 1)  # ENRICHED format: interpreted fields after GS
    fields = {k: v for k, v in _KV.findall(body[0])}
    if len(body) > 1:
        fields.update({f"_{k}": _unquote(v) for k, v in _KV.findall(body[1])})
    return m["type"], float(m["ts"]), m["serial"], fields


def _sockaddr(hexstr: str) -> tuple[str, int] | None:
    try:
        b = bytes.fromhex(hexstr)
    except ValueError:
        return None
    if len(b) < 8:
        return None
    family = int.from_bytes(b[0:2], "little")
    port = int.from_bytes(b[2:4], "big")
    if family == 2:  # AF_INET
        return ".".join(str(x) for x in b[4:8]), port
    if family == 10 and len(b) >= 24:  # AF_INET6
        raw = b[8:24]
        return ":".join(f"{int.from_bytes(raw[i:i + 2], 'big'):x}" for i in range(0, 16, 2)), port
    return None


def _syscall_name(sc: dict[str, str]) -> str:
    if sc.get("_SYSCALL"):
        return sc["_SYSCALL"]
    raw = sc.get("syscall", "")
    if not raw.isdigit():
        return raw
    table = _SYSCALLS_AARCH64 if sc.get("arch", "").lower() in _ARCH_AARCH64 else _SYSCALLS_X86_64
    return table.get(raw, raw)


def _join(cwd: str, name: str) -> str:
    if not name or name.startswith("/") or not cwd:
        return name
    return cwd.rstrip("/") + "/" + (name[2:] if name.startswith("./") else name)


class _Group:
    __slots__ = ("ts", "serial", "records")

    def __init__(self, ts: float, serial: str) -> None:
        self.ts, self.serial, self.records = ts, serial, []


def _events_from_group(g: _Group, host: str, images: dict[str, str]) -> list[Event]:
    by_type: dict[str, list[dict[str, str]]] = {}
    for t, f in g.records:
        by_type.setdefault(t, []).append(f)
    sc = (by_type.get("SYSCALL") or [None])[0]
    if sc is None:
        return []
    name = _syscall_name(sc)
    if sc.get("success", "yes") != "yes":
        return []
    pid, ppid = sc.get("pid", ""), sc.get("ppid", "")
    exe = _unquote(sc.get("exe", ""))
    comm = _unquote(sc.get("comm", ""))
    cwd = _decode_hex((by_type.get("CWD") or [{}])[0].get("cwd", ""))
    paths = by_type.get("PATH", [])
    ts = datetime.fromtimestamp(g.ts, tz=timezone.utc)
    attrs: dict[str, str] = {
        "host": host, "channel": "auditd", "syscall": name, "audit_serial": g.serial,
        "pid": pid, "ppid": ppid, "uid": sc.get("uid", ""), "auid": sc.get("auid", ""), "comm": comm,
    }
    if sc.get("key") and sc["key"] != "(null)":
        attrs["audit_key"] = _decode_hex(sc["key"])
    if sc.get("ses"):
        attrs["session"] = sc["ses"]
    actor = process_ref(pid, exe or images.get(pid, ""))
    out: list[tuple[EventType, str, str, str]] = []
    if name in _EXEC:
        parent_img = images.get(ppid, "")
        ex = (by_type.get("EXECVE") or [{}])[0]
        try:
            argc = int(ex.get("argc", "0"))
        except ValueError:
            argc = 0
        argv = [_decode_hex(ex.get(f"a{i}", "")) for i in range(argc)]
        attrs["command_line"] = " ".join(a for a in argv if a)[:2048]
        attrs["image"] = exe
        attrs["parent_image"] = parent_img
        images[pid] = exe
        out.append((EventType.PROCESS_START, process_ref(ppid, parent_img), "spawned", process_ref(pid, exe)))
    elif name in _OPEN:
        items = [p for p in paths if p.get("nametype") not in ("PARENT",)]
        target = _join(cwd, _decode_hex(items[-1].get("name", ""))) if items else ""
        if target:
            flag_arg = sc.get("a2" if name in ("openat", "openat2") else "a1", "0")
            try:
                flags = int(flag_arg, 16)
            except ValueError:
                flags = 0
            write = name == "creat" or bool(flags & _O_WRITE_MASK) or any(p.get("nametype") == "CREATE" for p in paths)
            if write:
                out.append((EventType.FILE_WRITE, actor, "wrote", f"file:{target}"))
            elif attrs.get("audit_key"):
                out.append((EventType.FILE_READ, actor, "read", f"file:{target}"))
    elif name in _DELETE:
        victims = [p for p in paths if p.get("nametype") == "DELETE"]
        for v in victims:
            out.append((EventType.FILE_DELETE, actor, "deleted", f"file:{_join(cwd, _decode_hex(v.get('name', '')))}"))
    elif name == "connect":
        sa = (by_type.get("SOCKADDR") or [{}])[0].get("saddr", "")
        addr = _sockaddr(sa) if sa else None
        if addr:
            attrs["dst_ip"], attrs["dst_port"] = addr[0], str(addr[1])
            out.append((EventType.NETWORK_CONNECT, actor, "connected", f"ip:{addr[0]}:{addr[1]}"))
    events = []
    for et, a, action, obj in out:
        events.append(finalize_event(Event(
            event_id="pending", timestamp=ts, event_type=et, actor=a, action=action, object=obj,
            source_artifact="auditd", source_reliability=SourceReliability.B,
            attributes={k: v for k, v in attrs.items() if v},
        )))
    return events


def load_auditd(path: str | Path, *, host: str = "", stats: LoadStats | None = None) -> list[Event]:
    """Parse a raw (or ``ausearch --raw``) audit log into normalized events."""
    stats = stats if stats is not None else LoadStats()
    host = host or "linux"
    groups: OrderedDict[str, _Group] = OrderedDict()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            parsed = parse_line(line)
            if parsed is None:
                stats.bad_rows += 1
                continue
            rtype, ts, serial, fields = parsed
            g = groups.get(serial)
            if g is None:
                g = groups[serial] = _Group(ts, serial)
            g.records.append((rtype, fields))
    images: dict[str, str] = {}
    events: list[Event] = []
    for g in sorted(groups.values(), key=lambda x: (x.ts, int(x.serial))):
        stats.rows += 1
        evs = _events_from_group(g, host, images)
        if evs:
            stats.mapped += 1
            events.extend(evs)
        else:
            kinds = {t for t, _ in g.records}
            sc = next((f for t, f in g.records if t == "SYSCALL"), None)
            stats.unmapped[f"auditd:{_syscall_name(sc) if sc else '/'.join(sorted(kinds))}"] += 1
    events.sort(key=lambda e: e.timestamp)
    return events


def looks_like_audit_log(head: str) -> bool:
    return head.startswith(("type=", "node=")) and "msg=audit(" in head


__all__ = ["load_auditd", "looks_like_audit_log", "parse_line"]
