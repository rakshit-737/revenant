# Limitations & roadmap

REVENANT is a research prototype. These are the honest boundaries; several are inherent to
the available public ground truth or need hardware/data that this project deliberately does
not require.

## Limitations

- **B1** covers process lineage and process→action edges only. Cross-entity edges (dropped
  file executed, logon session) have no public ground truth, so they are untested.
- **B2** uses REVENANT's own heuristics to decide "found", so it measures ranking and
  grouping, not detection quality. The gain over a flat suspicion-sorted list is small.
- **B3** precision is low, and the labels come from file names. Service-crash style log
  suppression is not modelled.
- `.evtx` parsing through python-evtx is slow (about 21 records/s on the benchmark machine).
  Converting to JSON first with `evtx_dump` is much faster.
- No published numbers exist for these exact tasks on these corpora. The comparisons are
  against baselines only.
- Anti-forensics checks on MFT against `$LogFile`/`$UsnJrnl` are limited to plaso's
  `$SI`/`$FN` fields. There is no raw NTFS parser.
- The LLM report-drafting assistant from the spec is intentionally **not** built. No claim
  comes from a model ([ADR 0001](adr/0001-rules-not-ml-for-causal-claims.md)).

## Roadmap

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
