#!/usr/bin/env python3
"""Probe the ATLASv2 download link with HEAD requests (no dataset bytes are downloaded).

ATLASv2 (Riddle, Westfall and Bates, arXiv:2401.01341) re-runs ATLAS's ten
attacks with Sysmon and Carbon Black telemetry. Its README
(https://bitbucket.org/sts-lab/atlasv2) states the data is 12 GB compressed /
160 GB uncompressed and hosts it on a University of Illinois Box share. This
script records whether that share answers, with which status, final URL,
content type and length, so the README's "not probed" limitation is replaced
by a dated observation.

Usage::

    python scripts/probe_atlasv2.py --out out/atlasv2_probe.json
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

URL = "https://uofi.box.com/s/feunur7280afxrfeb0af73recexa73yc"
README = "https://bitbucket.org/sts-lab/atlasv2 (README: 12 GB compressed, 160 GB uncompressed)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D102 - report the redirect instead of following it
        return None


def _ask(url: str, method: str, timeout: float, follow: bool) -> dict:
    """One request; the response body is never read."""
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "revenant-link-probe"})
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:  # nosec B310 - fixed https URL
            h = resp.headers
            return {"method": method, "status": resp.status, "final_url": resp.geturl(),
                    "content_type": h.get("Content-Type"), "content_length": h.get("Content-Length")}
    except urllib.error.HTTPError as exc:
        return {"method": method, "status": exc.code, "location": exc.headers.get("Location"),
                "content_type": exc.headers.get("Content-Type")}
    except (urllib.error.URLError, OSError) as exc:
        return {"method": method, "status": None, "error": repr(exc)}


def probe(url: str = URL, timeout: float = 60.0) -> dict:
    """HEAD the share link; GET it without following the redirect (no body read); HEAD the redirect target."""
    steps = [_ask(url, "HEAD", timeout, follow=True), _ask(url, "GET", timeout, follow=False)]
    target = steps[1].get("location")
    if target:
        steps.append({"url": target, **_ask(target, "HEAD", timeout, follow=True)})
    out: dict = {"url": url, "stated_size": README, "requests": steps,
                 "probed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    alive = any(s.get("status") in (200, 301, 302, 303, 307, 308) for s in steps)
    direct = any(s.get("status") == 200 and "html" not in (s.get("content_type") or "").lower()
                 and s.get("content_length") for s in steps)
    out["link_alive"] = alive
    out["is_direct_file"] = direct
    out["interpretation"] = (
        "the link serves a file directly" if direct else
        "the share link redirects to Box's web app, which serves HTML and rejects HEAD: no file URL is exposed "
        "for a scripted, checksum-pinned download, and the stated 160 GB uncompressed exceeds a standard "
        "GitHub-hosted runner's disk (14 GB SSD guaranteed)" if alive else
        "the link did not answer")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    res = probe()
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(res, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
