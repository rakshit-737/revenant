"""Entity identity helpers shared by parsers, fusion and the rule engine.

Different artefacts spell the same entity differently:

* Sysmon / 4688 give full image paths (``C:\\Windows\\System32\\cmd.exe``),
  Volatility's ``ImageFileName`` is the basename truncated to 14 chars,
  plaso prefetch gives ``CMD.EXE``.
* Sysmon logs decimal PIDs, Security 4688 logs hex PIDs (``0x1410``).
* Hosts appear as ``WORKSTATION5`` or ``WORKSTATION5.theshire.local``.

The rule engine therefore never compares raw strings. It compares *keys*
produced here, which are deliberately lossy in documented ways (see
docs/adr/0003-entity-keys.md).
"""

from __future__ import annotations

import re

from .models import Event

IMAGE_KEY_LEN = 14  # Volatility's EPROCESS.ImageFileName limit
_PROC_RE = re.compile(r"^process:(?P<pid>[^:]*):(?P<image>.*)$", re.IGNORECASE)


def norm_path(path: str | None) -> str:
    """Lower-case, forward slashes, stripped quotes."""
    if not path:
        return ""
    return path.strip().strip('"').replace("\\", "/").lower()


def image_key(image: str | None) -> str:
    """Basename of an image path, lower-cased and truncated like EPROCESS."""
    p = norm_path(image)
    base = p.rsplit("/", 1)[-1]
    return base[:IMAGE_KEY_LEN]


def norm_pid(pid: object) -> str:
    """Normalise decimal or ``0x`` hex PIDs to a decimal string."""
    if pid is None:
        return ""
    s = str(pid).strip()
    if not s or s in {"-", "?"}:
        return ""
    try:
        return str(int(s, 16)) if s.lower().startswith("0x") else str(int(s))
    except ValueError:
        return s


def norm_host(host: str | None) -> str:
    """Short, lower-case host name (drops the DNS suffix)."""
    if not host:
        return ""
    return str(host).strip().split(".")[0].lower()


def norm_user(user: str | None) -> str:
    """``DOMAIN\\user`` / ``user@domain`` -> ``user`` (lower-case)."""
    if not user:
        return ""
    u = str(user).strip()
    if "\\" in u:
        u = u.rsplit("\\", 1)[-1]
    if "@" in u:
        u = u.split("@", 1)[0]
    return u.lower()


def process_ref(pid: object, image: str | None) -> str:
    """Canonical ``process:<pid>:<image>`` reference used in Event actor/object."""
    return f"process:{norm_pid(pid) or '?'}:{image or ''}"


def split_process_ref(ref: str) -> tuple[str, str] | None:
    """Split a process reference into ``(pid, image)``; return None if it does not parse."""
    m = _PROC_RE.match(ref or "")
    if not m:
        return None
    return norm_pid(m.group("pid")), m.group("image")


def process_key(host: str, ref: str) -> str | None:
    """Engine key for a ``process:`` reference: ``host|pid|image-basename``."""
    parts = split_process_ref(ref)
    if parts is None:
        return None
    pid, image = parts
    if not pid:
        return None
    return f"{norm_host(host)}|{pid}|{image_key(image)}"


def event_host(ev: Event) -> str:
    """Return the normalised host name of an event."""
    return norm_host(ev.attributes.get("host", ""))


def actor_process_key(ev: Event) -> str | None:
    """Return the host-scoped process key of an event's actor, or None."""
    return process_key(event_host(ev), ev.actor)


def object_process_key(ev: Event) -> str | None:
    """Return the host-scoped process key of an event's object, or None."""
    return process_key(event_host(ev), ev.object)
