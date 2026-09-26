"""Court-style report generator (Markdown, HTML, optional PDF).

Structure follows what a forensic examiner's report needs to survive
scrutiny:

1. **Scope & evidence** -- every acquired artefact with its SHA-256.
2. **Method** -- what the engine does and does not claim.
3. **Findings** -- ranked incident stories. Every line cites the event id,
   the source artefact + reliability grade and the event's integrity hash, so
   no sentence is unsupported. Suspicion (what it looks like) and confidence
   (how well the evidence supports the causal links) are reported separately.
4. **Tampering indicators** -- anti-forensics findings.
5. **What remains uncertain** -- silent windows (reported as *unknown*),
   unparsed event types, unreadable artefacts, rule-inference caveats.
6. **Chain of custody** -- ledger size, head hash and verification result.

No LLM is involved: text is templated from derived facts only (the spec's
"what AI should NOT be trusted to do" boundary).
"""

from __future__ import annotations

import html
import re
from typing import TYPE_CHECKING

from .attack import TACTICS
from .graph import ProvenanceGraph
from .models import IncidentStory, ProvenanceChain
from .stories import story_breakdown, story_gaps

if TYPE_CHECKING:  # pragma: no cover
    from .pipeline import Analysis


def _hop_line(graph: ProvenanceGraph, event_id: str, analysis: Analysis | None = None) -> str:
    e = graph.get_event(event_id)
    if e is None:
        return f"- [{event_id}] (missing event)"
    h = (e.integrity_hash or "")[:12]
    extra = ""
    if analysis is not None:
        t = analysis.tags.get(event_id)
        if t and t.techniques:
            extra = " **[" + ", ".join(sorted({x[0] for x in t.techniques})) + "]**"
        n = len(graph.corroborations.get(event_id, []))
        if n:
            srcs = sorted(graph.sources_for(event_id))
            extra += f" (corroborated by {n}: {'/'.join(srcs)})"
    cmd = e.attributes.get("command_line", "")
    cmd = f" `{cmd[:140]}`" if cmd else ""
    host = e.attributes.get("host", "")
    host = f"[{host}] " if host else ""
    return (
        f"- `{e.event_id}` {e.timestamp.isoformat()} {host}**{e.actor}** {e.action} "
        f"*{e.object}*{cmd}{extra} (source: {e.source_artifact}/{e.source_reliability.value}, "
        f"sha256:{h}...)"
    )


def narrative_for(chain: ProvenanceChain, graph: ProvenanceGraph) -> str:
    lines: list[str] = []
    stages = " -> ".join(s.value for s in chain.stages) or "n/a"
    lines.append(f"### {chain.chain_id} - {chain.grade.value} (score {chain.confidence_score})")
    lines.append(f"**Kill-chain stages:** {stages}")
    lines.append("")
    lines.append("**Evidence (each hop cites its artifact + hash):**")
    for eid in chain.event_ids:
        lines.append(_hop_line(graph, eid))
    if chain.tampering_flags:
        lines.append("")
        lines.append("**Tampering indicators (confidence reduced):**")
        for f in chain.tampering_flags:
            lines.append(f"- {f}")
    return "\n".join(lines)


def story_narrative(story: IncidentStory, analysis: Analysis, *, max_hops: int = 40) -> str:
    g = analysis.graph
    b = story_breakdown(story, g)
    root = g.get_event(story.root_event_id)
    lines = [
        f"### {story.story_id} - suspicion {story.suspicion:.2f}, confidence {story.grade.value} "
        f"({story.confidence_score:.2f})",
        "",
        f"- **Root:** `{story.root_event_id}` {root.object if root else '?'}",
        f"- **Hosts:** {', '.join(story.hosts) or 'n/a'}",
        f"- **ATT&CK techniques:** {', '.join(story.techniques) or 'none tagged'}",
        f"- **Tactics:** {', '.join(f'{t} ({TACTICS.get(t, t)})' for t in story.tactics) or 'n/a'}",
        f"- **Kill-chain stages:** {' -> '.join(s.value for s in story.stages) or 'n/a'}",
        f"- **Confidence breakdown:** reliability {b.reliability:.2f}, corroboration "
        f"{b.corroboration:.2f}, temporal fit {b.temporal_fit:.2f}, edge strength "
        f"{b.edge_strength:.2f}, tamper penalty x{b.penalty:.2f}",
        f"- **Events:** {len(story.event_ids)} shown, {story.omitted_events} benign leaf actions omitted, "
        f"{len(story.edges)} causal edges",
        "",
        "**Evidence (time order; each line cites event id, source/reliability and hash):**",
    ]
    ids = story.event_ids
    if len(ids) > max_hops:  # keep suspicious events + the root, elide the rest
        keep = {story.root_event_id} | {
            i for i in ids if (t := analysis.tags.get(i)) and t.techniques
        }
        shown = [i for i in ids if i in keep][:max_hops]
        for i in shown:
            lines.append(_hop_line(g, i, analysis))
        lines.append(f"- ... {len(ids) - len(shown)} further events in this story (see JSON export)")
    else:
        for i in ids:
            lines.append(_hop_line(g, i, analysis))
    rules = sorted({e.rule_name for e in story.edges})
    if rules:
        lines += ["", f"**Causal rules used:** {', '.join(rules)}"]
    if story.tampering_flags:
        lines += ["", "**Tampering indicators touching this story:**"]
        lines += [f"- {f}" for f in story.tampering_flags]
    gaps = story_gaps(g, story)
    if gaps:
        lines += ["", "**Unknown windows inside this story:**"]
        lines += [f"- {x}" for x in gaps]
    return "\n".join(lines)


def generate_report(analysis: Analysis, *, top: int = 5, title: str = "Forensic Reconstruction Report") -> str:
    g = analysis.graph
    parts: list[str] = [
        f"# REVENANT - {title}",
        "",
        "> Lab-only analysis. Automatically generated from derived facts; every claim cites evidence.",
        "",
        "## Summary",
        f"- Events ingested: {len(analysis.events)}",
        f"- Cross-artefact corroborations: {analysis.corroborations}",
        f"- Causal edges inferred: {len(g.edges)}",
        f"- Incident stories: {len(analysis.stories)}",
        f"- Candidate chains (path view): {len(analysis.chains)}",
        f"- Tampering indicators: {len(analysis.indicators)}",
        f"- Custody ledger verified: {analysis.ledger.verify()}",
        "",
    ]
    if analysis.artefacts:
        parts += ["## Scope and evidence", "", "| Artefact | SHA-256 |", "| --- | --- |"]
        for a in analysis.artefacts[:50]:
            parts.append(f"| `{a['path'].replace(chr(92), '/').rsplit('/', 1)[-1]}` | `{a['sha256']}` |")
        if len(analysis.artefacts) > 50:
            parts.append(f"| ... {len(analysis.artefacts) - 50} more | |")
        parts.append("")
    parts += [
        "## Method",
        "",
        "Events were normalised to an actor-action-object schema and hashed on ingest. "
        "Causal edges were inferred by named, deterministic rules under entity (host, PID, image, "
        "GUID, logon id) and temporal constraints. Stories group the causal subtree below the first "
        "non-system ancestor of each suspicious event. Suspicion comes from transparent ATT&CK "
        "heuristics plus per-case rarity; confidence comes from source reliability, corroboration, "
        "temporal fit and rule strength, reduced by tampering indicators.",
        "",
    ]

    if analysis.stories:
        parts.append("## Findings: ranked incident stories")
        for s in analysis.stories[:top]:
            parts += ["", story_narrative(s, analysis)]
        parts.append("")
    if analysis.chains:
        parts.append("## Ranked incident narratives (path view)")
        for chain in analysis.chains[:top]:
            parts += ["", narrative_for(chain, g)]
        parts.append("")
    if not analysis.stories and not analysis.chains:
        parts += ["## Findings", "_No causal chains reconstructed._", ""]

    tamper = [i for i in analysis.indicators if i.indicator != "log_gap"]
    parts.append("## Tampering indicators")
    if tamper:
        for i in tamper[:50]:
            parts.append(f"- **{i.indicator}** ({i.severity}): {i.detail} [{', '.join(i.event_ids[:3])}]")
        if len(tamper) > 50:
            parts.append(f"- ... {len(tamper) - 50} more")
    else:
        parts.append("- None detected.")

    parts += ["", "## What remains uncertain"]
    gaps = [i for i in analysis.indicators if i.indicator == "log_gap"]
    for gap in gaps[:20]:
        parts.append(f"- {gap.detail}")
    if not gaps:
        parts.append("- No unexplained timeline gaps above threshold were detected.")
    ls = analysis.load_stats or {}
    if ls.get("top_unmapped"):
        un = ", ".join(f"{k} x{v}" for k, v in ls["top_unmapped"][:8])
        parts.append(f"- Event types present but not interpreted (not used in any claim): {un}.")
    if ls.get("unreadable_files"):
        parts.append(f"- {len(ls['unreadable_files'])} artefact(s) could not be opened (e.g. quarantined by "
                     "endpoint AV); anything they contain is absent from this analysis.")
    parts += [
        "- Causal edges are rule-inferred correlations under temporal/entity constraints, not proof of intent.",
        "- Suspicion is heuristic (named ATT&CK patterns + rarity); absence of a tag is not evidence of innocence.",
        "- Confidence grades derive from source reliability, corroboration and temporal fit; they are "
        "calibrated estimates, not certainties.",
        "",
        "## Chain of custody",
        f"- Ledger records: {len(analysis.ledger.records)}",
        f"- Ledger head: `{analysis.ledger.records[-1].record_hash if analysis.ledger.records else '-'}`",
        f"- Tamper-evident hash chain intact: {analysis.ledger.verify()}",
    ]
    return "\n".join(parts)


# --------------------------------------------------------------------- HTML
_CSS = """
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1b1f24}
h1{border-bottom:2px solid #333}h2{margin-top:2rem;border-bottom:1px solid #ccc}
code{font:12px ui-monospace,Consolas,monospace;background:#f3f4f6;padding:1px 3px;border-radius:3px;word-break:break-all}
li{margin:.15rem 0}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:3px 8px}
blockquote{color:#555;border-left:3px solid #aaa;margin:0;padding-left:1rem}
@media print{body{max-width:none;margin:0}}
"""


def _inline(s: str) -> str:
    s = html.escape(s, quote=False)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<![\w*])\*([^*]+)\*(?!\w)", r"<em>\1</em>", s)
    return s


def markdown_to_html(md: str, title: str = "REVENANT report") -> str:
    """Render the report's limited Markdown subset (no external dependency)."""
    out: list[str] = []
    in_list = in_table = False
    for line in md.splitlines():
        if in_list and not line.startswith("- "):
            out.append("</ul>")
            in_list = False
        if in_table and not line.startswith("|"):
            out.append("</table>")
            in_table = False
        if line.startswith("### "):
            out.append(f"<h3>{_inline(line[4:])}</h3>")
        elif line.startswith("## "):
            out.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{_inline(line[2:])}</h1>")
        elif line.startswith("> "):
            out.append(f"<blockquote>{_inline(line[2:])}</blockquote>")
        elif line.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(line[2:])}</li>")
        elif line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= {"-", " "} for c in cells):
                continue
            if not in_table:
                out.append("<table>")
                in_table = True
            out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
        elif line.strip():
            out.append(f"<p>{_inline(line)}</p>")
    if in_list:
        out.append("</ul>")
    if in_table:
        out.append("</table>")
    body = "\n".join(out)
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8><title>{html.escape(title)}</title>"
            f"<style>{_CSS}</style></head><body>{body}</body></html>")


def generate_html(analysis: Analysis, *, top: int = 5) -> str:
    return markdown_to_html(generate_report(analysis, top=top))


def write_pdf(analysis: Analysis, path: str, *, top: int = 5) -> str:
    """Render the report to PDF with WeasyPrint (optional ``[pdf]`` extra)."""
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]
    except Exception as exc:  # ImportError, or OSError when Pango is missing
        raise RuntimeError(
            "PDF export needs WeasyPrint and its native Pango libraries: pip install 'revenant[pdf]'. "
            "Alternatively open the HTML report and print to PDF."
        ) from exc
    HTML(string=generate_html(analysis, top=top)).write_pdf(path)
    return path
