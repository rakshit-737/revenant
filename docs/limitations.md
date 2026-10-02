# Limitations & roadmap

REVENANT is a research prototype. These are the honest boundaries; several are inherent to
the available public ground truth or need hardware/data that this project deliberately does
not require.

## Limitations

- **Story confidence is not calibrated.** Edge constants are calibrated per rule against
  GUID truth, but story confidence is a hand-weighted sum (0.3/0.3/0.2/0.2) with hand-set grade
  cut-offs, and the GUID rules keep hand-set confidences. No benchmark yet shows CONFIRMED
  stories are correct more often than HIGH ones.
- **Stories do not speed up triage (B2).** Under equal reading budgets they are slightly worse
  than a suspicion-sorted flat list (hit@1 0.28 vs 0.36, p = 0.06). B2 uses REVENANT's own
  heuristics to decide "found", and the calibration table was fitted on the same captures.
- **B1** gains over PID-nearest on one corpus (OTRF atomic) and come from the image-keyed
  fallback rules; four other corpora show no difference. Only process lineage and
  process→action edges have ground truth; cross-entity edges are exercised only by the live
  auditd consistency check.
- **B3** has 10 positives and file-name labels; service-crash style log suppression and MRU
  deletes are not modelled.
- `.evtx` parsing through python-evtx is slow (about 21 records/s on the benchmark machine).
  Converting to JSON first with `evtx_dump` is much faster.
- ATLAS's published numbers are recomputed from its released outputs (its model was not
  re-run), and REVENANT is not scored on ATLAS or ATLASv2: the labels are entity names for a
  sequence model rather than cause-effect pairs, no ATLAS parser exists yet, and the TF 2.3
  container and the ATLASv2 Box download have not been set up. Story ranking (B2) covers OTRF
  atomic only.
- B1 corpora with fewer than 10 scorable captures report no CI.
- Anti-forensics checks on MFT against `$LogFile`/`$UsnJrnl` are limited to plaso's
  `$SI`/`$FN` fields. There is no raw NTFS parser.
- The LLM report-drafting assistant from the spec is intentionally **not** built. No claim
  comes from a model ([ADR 0001](adr/0001-rules-not-ml-for-causal-claims.md)).

## Roadmap

- [ ] Score REVENANT under the ATLAS protocol, with a BackTracker-style reachability baseline
- [ ] Re-run ATLAS's released model (TensorFlow 2.3) and retrain with seeds
- [ ] Story-level confidence validation against labelled stories
- [ ] `evtx_dump` / Hayabusa JSON ingest for fast `.evtx` handling
- [ ] Event-log service-crash and MRU-deletion tamper indicators (the B3 misses)
- [ ] Labelled cross-entity edges from a self-captured lab scenario
- [ ] Timesketch importer/exporter
- [ ] PostgreSQL custody backend

## Design stance on AI

The core uses rules and a graph on purpose. Courts distrust black boxes, so explainability is
a design constraint. Every edge names the rule that produced it, and every report line cites
an event id and hash. The only learned part is the per-rule calibration table, fitted from
public ground truth and shipped as readable JSON.
