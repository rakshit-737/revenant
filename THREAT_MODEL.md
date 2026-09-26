# Threat Model - REVENANT

## Scope

REVENANT reconstructs incident narratives from forensic artifacts. It is a
read-only analytical tool operated by a DFIR analyst on evidence they are
authorized to examine, in an isolated lab. It produces reports that may be used
in investigations, so **evidentiary integrity is the primary asset**.

## Assets

| Asset | Why it matters |
| --- | --- |
| Source artifacts (timelines, memory, logs) | Must never be mutated by the tool |
| Per-event integrity hashes | Prove an event was not altered post-ingest |
| Custody ledger | Tamper-evident record of what the tool did and when |
| Derived narratives + confidence grades | May inform legal/IR decisions; a wrong causal claim is costly |

## Trust boundaries

- **Source artifacts are untrusted input.** They may be incomplete, contain
  attacker-controlled fields, or be deliberately tampered (anti-forensics).
- The tool **treats artifact-supplied timestamps as claims, not truth** and
  cross-checks them; it never fabricates events to fill gaps.
- The tool **never writes back** to source artifacts. Ingest is one-way.
- The custody ledger is **append-only and hash-chained**; each record commits to
  the previous record's hash, so silent edits/deletions break `verify()`.

## Adversary: anti-forensics (modeled)

| Technique | REVENANT response |
| --- | --- |
| Timestomping (MFT vs `$LogFile` mismatch) | `detect_timestomp` flags the event; chain confidence is penalized |
| Log deletion / silent gaps | `detect_log_gaps` reports the window as *unknown* rather than inferring through it |
| Post-ingest evidence tampering | `verify_event` / ledger `verify()` fail; `detect_hash_mismatch` flags it |

Confidence is *reduced*, never silently absorbed: a flagged chain carries its
tampering indicators into the report.

## Adversary: the tool itself producing over-confident claims

- Causal edges are explicitly labelled as **rule-inferred correlations under
  temporal/entity constraints**, not proof of intent.
- Confidence grades are calibrated estimates derived from documented weights
  (`confidence.WEIGHTS`), surfaced in the report, and floored so a single strong
  signal cannot manufacture certainty.
- Every narrative hop cites its event id, source artifact, and hash - no
  unsupported sentences.

## Out of scope

- Network/host compromise of the analyst workstation (assume a trusted analyst
  on an isolated system).
- Cryptographic non-repudiation across organizations (the ledger is
  tamper-*evident*, not a notarized signature chain - a documented TODO).
- Real malware handling / detonation (see SPECIMEN, a separate project).
