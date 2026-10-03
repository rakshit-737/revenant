"""ATLAS preprocessed-log connector (Alsaheel et al., USENIX Security 2021).

The ATLAS release (https://github.com/purseclab/ATLAS, Apache-2.0) ships every
attack's logs in the authors' *preprocessed* form: one comma-separated line
per Windows Security-audit, DNS or Firefox-HTTP record, sorted by time. Each
line has 20 fields (see `FIELDS`); the time field is ``day_of_year * 86400 +
seconds_of_day`` in the victim's local clock (no year).

**Ground truth is stripped here.** ATLAS's ``preprocess.py`` appends a
label to the last field of every line: ``-LA+`` / ``-LB+`` / ``-LD+`` when
the line contains one of the attack's malicious entity names, ``-LA-`` etc.
otherwise. `strip_label` removes that suffix before anything else reads
the line, so no REVENANT attribute can carry the label
(``tests/test_atlas.py`` asserts this).

Mapping (documented in ``docs/atlas-mapping.md``):

=====================================  =======================================
line                                   normalized event(s)
=====================================  =======================================
Security, first sighting of a          ``process_start`` (parent = ``ppid``,
(pid, image basename)                  image = path)
Security with an IP endpoint           ``network_connect`` to the remote end
Security with object type ``file``     ``file_write`` (WriteData/AppendData),
                                       ``file_read`` or ``file_delete``
DNS response                           ``dns_query`` (domain, resolved IP)
Firefox HTTP request / response        ``web_visit`` (URL, host, referer)
=====================================  =======================================

The preprocessed Security lines carry no event id, so a process start is
inferred from the first line that names a (pid, image) pair; later lines of
that pair are actions. The source is rated C (an analyst's preprocessed
export, not the raw evidence).
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..entities import image_key, process_ref
from ..integrity import finalize_event
from ..models import Event, EventType, SourceReliability
from .otrf import LoadStats

FIELDS = (
    "time", "dns_domain", "dns_ip", "pid", "ppid", "image", "src_ip", "src_port", "dst_ip", "dst_port",
    "http_type", "url", "post_url", "http_code", "http_host", "referer", "location",
    "object_type", "object_name", "direction",
)
_LABEL = re.compile(r"-L[A-Z][+-]\s*$")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# the logs carry no year; any fixed leap-free base keeps the order and gaps exact
BASE_YEAR = 2018
# address prefixes that are never a remote peer (a string list, not a bind address)
_NOT_REMOTE = ("127.", "0.0.0.0", "255.255.255.255", "::1", "fe80", "ff02", "224.", "239.")  # nosec B104


def strip_label(line: str) -> str:
    """Remove ATLAS's trailing ground-truth label (``-LA+``, ``-LD-`` ...) and the newline."""
    return _LABEL.sub("", line.rstrip("\r\n"))


def split_record(line: str) -> dict[str, str] | None:
    """Split one preprocessed line (label already stripped or not) into named fields.

    Returns None for blank or malformed lines.
    """
    body = strip_label(line)
    if not body.strip():
        return None
    parts = body.split(",")
    if len(parts) < 10 or not parts[0].strip().isdigit():
        return None
    parts += [""] * (len(FIELDS) - len(parts))
    return {k: v.strip() for k, v in zip(FIELDS, parts[: len(FIELDS)])}


def to_datetime(value: str) -> datetime:
    """Convert ATLAS's ``day_of_year * 86400 + seconds`` time to a UTC datetime in `BASE_YEAR`."""
    return datetime(BASE_YEAR, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=int(value) - 86400)


def _image(v: str) -> str:
    return "" if v in ("", "-") else v


def _ip(v: str) -> str:
    return v if v and v != "-" else ""


def local_addresses(records: Iterable[dict[str, str]], top: int = 1) -> set[str]:
    """The host's own address(es): the IPv4 endpoint(s) seen most often in its network records."""
    c: Counter = Counter()
    for r in records:
        for k in ("src_ip", "dst_ip"):
            ip = _ip(r[k])
            if _IPV4.match(ip) and not ip.startswith(_NOT_REMOTE):
                c[ip] += 1
    return {ip for ip, _ in c.most_common(top)}


def is_remote(ip: str, local: set[str]) -> bool:
    """True if ``ip`` is a routable peer: not one of the host's own, loopback, broadcast or multicast."""
    return bool(ip) and ip not in local and not ip.lower().startswith(_NOT_REMOTE)


def _file_action(accesses: str) -> tuple[EventType, str]:
    a = accesses.lower()
    if "writedata" in a or "appenddata" in a:
        return EventType.FILE_WRITE, "wrote"
    if "readdata" in a or "execute" in a:
        return EventType.FILE_READ, "read"
    if a.startswith("file_delete") or "_delete_" in a:
        return EventType.FILE_DELETE, "deleted"
    return EventType.FILE_READ, "read"


def iter_records(lines: Iterable[str], stats: LoadStats | None = None) -> Iterator[dict[str, str]]:
    """Yield the label-free field dict of every well-formed line."""
    for line in lines:
        if not line.strip():
            continue
        if stats is not None:
            stats.rows += 1
        r = split_record(line)
        if r is None:
            if stats is not None:
                stats.bad_rows += 1
            continue
        yield r


def records_to_events(records: list[dict[str, str]], *, host: str,
                      stats: LoadStats | None = None) -> list[Event]:
    """Map label-free ATLAS records (in file order) to normalized, hashed events."""
    stats = stats if stats is not None else LoadStats()
    local = local_addresses(records)
    images: dict[str, str] = {}  # pid -> image of its most recent sighting
    started: set[tuple[str, str]] = set()  # (pid, image basename) already started
    seen: set[tuple] = set()
    out: list[Event] = []
    calls = [0]  # emit() calls, duplicates included: a line that repeats a fact is still mapped

    def emit(ts: datetime, et: EventType, actor: str, action: str, obj: str, source: str,
             rel: SourceReliability, attrs: dict[str, str]) -> None:
        calls[0] += 1
        attrs = {k: v for k, v in attrs.items() if v}
        key = (ts, et, actor, action, obj, tuple(sorted(attrs.items())))
        if key in seen:  # ATLAS lines repeat within a second: one event per fact
            return
        seen.add(key)
        out.append(finalize_event(Event(event_id="pending", timestamp=ts, event_type=et, actor=actor,
                                        action=action, object=obj, source_artifact=source,
                                        source_reliability=rel, attributes=attrs)))

    for r in records:
        ts = to_datetime(r["time"])
        base = {"host": host, "channel": "atlas"}
        n_before = calls[0]
        if r["dns_domain"]:
            emit(ts, EventType.DNS_QUERY, "network:dns", "resolved", f"dns:{r['dns_domain']}", "atlas_dns",
                 SourceReliability.B, {**base, "domain": r["dns_domain"], "resolved_ip": _ip(r["dns_ip"])})
        elif r["http_type"]:
            url = r["url"] or r["location"]
            if url:
                emit(ts, EventType.WEB_VISIT, "browser:firefox", r["http_type"], f"url:{url}", "atlas_firefox",
                     SourceReliability.C, {**base, "http_host": r["http_host"], "referer": r["referer"],
                                           "location": r["location"], "http_code": r["http_code"],
                                           "post_url": r["post_url"]})
        else:
            pid, ppid, img = r["pid"], r["ppid"], _image(r["image"])
            if pid and img:
                key = (pid, image_key(img))
                if key not in started:
                    started.add(key)
                    parent_img = images.get(ppid, "") if ppid else ""
                    emit(ts, EventType.PROCESS_START, process_ref(ppid or None, parent_img), "spawned",
                         process_ref(pid, img), "atlas_security", SourceReliability.C,
                         {**base, "pid": pid, "ppid": ppid, "image": img, "parent_image": parent_img})
                images[pid] = img
            actor = process_ref(pid or None, img)
            src, dst = _ip(r["src_ip"]), _ip(r["dst_ip"])
            if src or dst:
                if is_remote(dst, local) or not is_remote(src, local):
                    remote, rport = dst, r["dst_port"]
                else:
                    remote, rport = src, r["src_port"]
                if remote:
                    emit(ts, EventType.NETWORK_CONNECT, actor, "connected", f"ip:{remote}:{rport or '?'}",
                         "atlas_security", SourceReliability.C,
                         {**base, "pid": pid, "image": img, "src_ip": src, "src_port": r["src_port"],
                          "dst_ip": dst, "dst_port": r["dst_port"], "remote_ip": remote})
            otype, oname = r["object_type"], r["object_name"]
            if oname and oname != "-" and otype.startswith("file"):
                et, action = _file_action(otype)
                emit(ts, et, actor, action, f"file:{oname}", "atlas_security", SourceReliability.C,
                     {**base, "pid": pid, "image": img, "accesses": otype[5:]})
        if calls[0] > n_before:
            stats.mapped += 1
        else:
            kind = "dns" if r["dns_domain"] else "http" if r["http_type"] else "security"
            stats.unmapped[f"atlas:{kind}"] += 1
    out.sort(key=lambda e: e.timestamp)
    return out


# ----------------------------------------------------------------- entity mapping
# REVENANT story entities -> the strings ATLAS's evaluate.py matches. evaluate.py marks a
# graph word or a log line as "predicted attack" when a predicted string is a *substring*
# of it, so each entity maps to the shortest form that is a substring of both ATLAS's
# graph word and its log line for that entity. Full rationale: docs/atlas-mapping.md.
MIN_LABEL_LEN = 4  # shorter strings are substrings of nearly every line
IGNORED_PROCESSES = frozenset({"system", "-", "unknown"})


def basename(path: str) -> str:
    """Lower-cased last component of a Windows or URL-style path."""
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].strip().lower()


def _name_forms(name: str) -> set[str]:
    # ATLAS's graph words drop spaces from paths; its log lines keep them
    return {name, name.replace(" ", "")} if " " in name else {name}


def entity_labels(ev: Event, local: set[str] | frozenset[str] = frozenset()) -> set[str]:
    """ATLAS label strings for the entities one REVENANT event names (docs/atlas-mapping.md).

    * process (``process:pid:image``; for a process start only the started process, not its
      parent) -> image basename, e.g. ``payload.exe``
    * file (``file:path``) -> basename, e.g. ``secret.docx``
    * network connection -> the remote IPv4/IPv6 address (never the host's own)
    * DNS answer -> the domain and the address it resolved to
    * web request -> the host name of the URL (port dropped)
    """
    from ..entities import split_process_ref
    from ..rules import url_host

    out: set[str] = set()
    # a process start names the started process; its parent is named by the parent's own start
    refs = (ev.object,) if ev.event_type == EventType.PROCESS_START else (ev.actor, ev.object)
    for ref in refs:
        p = split_process_ref(ref)
        if p and p[1]:
            b = basename(p[1])
            if b not in IGNORED_PROCESSES:
                out |= _name_forms(b)
    if ev.object.startswith("file:"):
        out |= _name_forms(basename(ev.object[5:]))
    if ev.event_type == EventType.NETWORK_CONNECT:
        ip = ev.attributes.get("remote_ip") or ev.object[3:].rsplit(":", 1)[0]
        if is_remote(ip, set(local)):
            out.add(ip)
    if ev.event_type == EventType.DNS_QUERY:
        out.add((ev.attributes.get("domain") or ev.object[4:]).lower())
        ip = ev.attributes.get("resolved_ip", "")
        if is_remote(ip, set(local)):
            out.add(ip)
    if ev.event_type == EventType.WEB_VISIT and ev.object.startswith("url:"):
        h = (ev.attributes.get("http_host") or url_host(ev.object[4:])).lower()
        if h and h != "localhost" and (not _IPV4.match(h) or is_remote(h, set(local))):
            out.add(h)
    return {s for s in out if len(s) >= MIN_LABEL_LEN}


def seed_events(events: Iterable[Event], symptom: str,
                local: set[str] | frozenset[str] = frozenset()) -> tuple[list[str], list[str]]:
    """Events that show the symptom entity, plus the addresses a symptom domain resolved to.

    A symptom matches an event when it equals one of the event's `entity_labels`. When the
    symptom is a domain name, every address a DNS answer gave for it is an alias and events
    naming an alias are seeds too. Returns ``(seed event ids, aliases)``.
    """
    symptom = symptom.strip().lower()
    events = list(events)
    labels = {e.event_id: entity_labels(e, local) for e in events}
    aliases = sorted({e.attributes["resolved_ip"] for e in events
                      if e.event_type == EventType.DNS_QUERY and e.attributes.get("resolved_ip")
                      and (e.attributes.get("domain") or "").lower() == symptom
                      and is_remote(e.attributes["resolved_ip"], set(local))})
    wanted = {symptom, *aliases}
    seeds = [e.event_id for e in events if labels[e.event_id] & wanted]
    return seeds, aliases


def load_atlas(path: str | Path, *, host: str = "", stats: LoadStats | None = None) -> list[Event]:
    """Parse one ATLAS preprocessed log (``testing_preprocessed_logs_*``) into normalized events.

    ``host`` defaults to ``atlas``; pass ``h1``/``h2`` for multi-host attacks.
    """
    stats = stats if stats is not None else LoadStats()
    with open(path, encoding="utf-8", errors="replace") as fh:
        records = list(iter_records(fh, stats))
    return records_to_events(records, host=host or "atlas", stats=stats)


def looks_like_atlas(head: str) -> bool:
    """Return True if a line looks like an ATLAS preprocessed record."""
    r = split_record(head)
    return r is not None and len(strip_label(head).split(",")) >= 19 and bool(_LABEL.search(head.rstrip()))


__all__ = ["FIELDS", "basename", "entity_labels", "is_remote", "load_atlas", "local_addresses", "looks_like_atlas",
           "records_to_events", "seed_events", "split_record", "strip_label", "to_datetime"]
