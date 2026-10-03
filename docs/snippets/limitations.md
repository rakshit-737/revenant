- **Causal-edge accuracy is at parity with a careful analyst heuristic, not above it.** On OTRF
  atomic REVENANT beats PID-nearest (macro F1 difference +0.194 [+0.129, +0.266], sign test
  p = 4.6e-7), but a PID-then-image-nearest heuristic (REVENANT's fallback idea without its
  keys, guard or fusion) comes within +0.008 [-0.000, +0.025] (p = 0.29). The other four corpora
  are easy for every method. B1 hides Sysmon GUIDs as a proxy for GUID-less sources; no
  4688-only, plaso or memory lineage is scored, and cross-entity edges (dropped file executed,
  logon session) have no public ground truth beyond the live auditd consistency check.
- **Calibration lowers ECE but does not improve ranking.** Fitted on APT29 and tested on atomic,
  ECE falls from 0.233 to 0.098 [0.011, 0.260], but AUROC is 0.66 [0.42, 0.94] vs 0.77 for the
  hand-set confidences and selective prediction gains nothing (every CI includes 0). 32,191
  atomic edges come from rules the APT29 table does not cover and keep hand-set confidences.
  The shipped table, now refitted on all atomic captures, has held-out ECE 0.034-0.057 on LSASS
  and APT29 (point estimates: under 10 captures each), higher than the stale table it replaces
  (0.019-0.027).
- **Story confidence is not calibrated.** It is a hand-weighted sum with hand-set grade
  cut-offs, and the GUID rules keep hand-set confidences. No benchmark checks that CONFIRMED
  stories are correct more often than HIGH ones.
- **Stories do not speed up triage (B2).** Under equal reading budgets hit@1 is 0.28 vs 0.36 for a
  suspicion-sorted flat list (lower, not significant: McNemar p = 0.064). B2 decides "found" with
  REVENANT's own heuristics, and the calibration table was fitted on the same captures.
- **Under the ATLAS protocol REVENANT is far below ATLAS** (entity F1 0.556 vs 0.913, worse on all
  10 attacks, p = 0.002). Its stories pull in the victim browser and its helpers, which ATLAS's
  labels exclude, and the entity mapping is a documented choice. Predicting the symptom alone
  scores entity F1 0.623 [0.545, 0.698]. ATLAS's released predictions were cleaned by hand; REVENANT's are not.
- **The ATLAS model re-run cannot reproduce the paper by itself.** `model.h5` re-runs and
  matches the release on 15/16 test graphs, but the paper's figures need the authors' manual
  cleaning step. ATLASv2 is not used: its Box link serves only an HTML share page (no scriptable,
  checksum-pinned file) and the data is 160 GB uncompressed. Retraining with seeds is not done.
- **Anti-forensics labels are still few.** B3 has 10 file-name positives; the new
  `logging_stopped` indicator was written after seeing B3's misses (recall 0.60 to 0.80, McNemar
  p = 0.50; not a held-out gain). On the 17 OTRF T1562.002 captures (B3b) REVENANT finds all 17 but so does a
  Sigma-equivalent rule set; pre-recording log clears and benign Sysmon EID 2 events keep
  precision at 0.29 [0.19, 0.42]. Remote Event Log crashes without a local trace and MRU deletions are not
  detected. There is no raw NTFS (`$LogFile`/`$UsnJrnl`) parser.
- B1 corpora with fewer than 10 scorable captures (APT29 day 1/2, LSASS, Log4Shell) report no CI.
- `.evtx` parsing through python-evtx is slow (211 records/s on a GitHub runner); converting with
  `evtx_dump` first is much faster.
- The LLM report-drafting assistant from the spec is intentionally not built; no claim comes
  from a model (ADR 0001).
