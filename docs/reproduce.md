# Reproduce

Everything here uses public data and pinned versions. The corpus-scale benchmarks are
designed to run on a GitHub Actions `ubuntu-24.04` runner (4 vCPU, 16 GB): no endpoint
antivirus interferes there and the 1.7 GB APT29 day-2 JSON fits in memory.

## Environment

- Python 3.10-3.14 (CI tests all five; the benchmarks run on 3.12 on `ubuntu-24.04` runners).
- `pip install -e ".[bench,evtx]"` for benchmarks, `".[dev,evtx,api]"` for tests,
  `".[docs]"` for this site (the docs workflow copies `results/*.png` into `docs/img/` before
  `mkdocs build --strict`; do the same locally).
- RAM: about 3 GB for OTRF atomic locally; APT29 day 2 needs a runner.

## 1. Tests and the committed fixture (2 minutes, no download)

```bash
python -m pytest -q -m "not realdata"
revenant analyze tests/fixtures/otrf_psexec_lsa_secrets.jsonl --top 1
```

Expected: all tests pass and the report's first story is
`story-a65f65fb66 - suspicion 0.87, confidence CONFIRMED (0.86)`. Without `-m "not realdata"`
the real-data tests also run when `$REVENANT_DATA` holds the corpora (about 10 minutes).

## 2. Data

```bash
python scripts/download_data.py                       # OTRF atomic + metadata, APT29 day 1, EVTX samples: ~86 MB compressed
python scripts/download_data.py --only otrf-lsass --only otrf-log4shell --only otrf-apt29-day2   # opt-in, ~64 MB compressed
python scripts/download_atlas.py --no-raw             # ATLAS experiments, ~0.35 GB (better on a runner); drop --no-raw for the raw logs too
```

Every archive is verified against `data/manifest.json` / `data/atlas_manifest.json`
(SHA-256, plus the git blob SHA-1 of the pinned upstream commit). Unpinned entries are
refused unless `--pin` is passed; mismatching files are deleted.

## 3. Corpus benchmarks

On GitHub: **Actions → bench-extended → Run workflow**. It downloads the data, refuses any
file that starts with an `MZ` header, and runs four jobs: `main` (B1 on atomic, APT29 day 1,
LSASS and Log4Shell with the calibration refit written into the package, then B2 with that
table, B3 and B3b), `day2` (B1 on APT29 day 2, scoring main's refitted table held out), `scale`
(B4) and `combine`, which merges the results with the run id and uploads `bench-results`
(the `results/` files and the refitted `rule_calibration.json`). Locally:

```bash
cd benchmarks
python bench_edges.py --extra          # B1 + calibration + ablations (+ --write-calibration to refit the table)
python bench_stories.py                # B2
python bench_antiforensics.py          # B3 (python-evtx is slow on Windows)
python bench_antiforensics_b3b.py      # B3b
python bench_scale.py                  # B4 (5 + 3x7 repetitions)
python make_figures.py                 # results/*.png, RESULTS.md, headline.md, stats.json, README table
```

| Job (run 37093169942) | Runner time | Key lines to expect |
|---|---|---|
| main | 7.6 min | `otrf_atomic 498142 events 142175 evaluable` · `revenant P=0.910 R=0.910 F1=0.910` · `pid_image_nearest_fused P=0.907 R=0.905 F1=0.906` · `pid_nearest_fused P=0.942 R=0.729 F1=0.822`; B2 hit@1 0.280 vs 0.364; B3 REVENANT TP 8 FP 24 FN 2; B3b 17/17 |
| day2 | 2.6 min | `otrf_apt29_day2 380796 events 166252 evaluable`, every method except v0.1 at F1 1.000 |
| scale | 2.5 min | about 12 s per end-to-end analysis; slopes `v0.1 2.006 v0.2 common 1.09` |
| combine | 0.5 min | `edges.json: [...5 corpora...]`, `[results] RESULTS.md, headline.md, stats.json + figures` |

To compare with the committed numbers, run `make_figures.py` and `git diff results/`.

## 4. ATLAS reproduction and REVENANT under the ATLAS protocol

On GitHub: **Actions → atlas-repro → Run workflow**. One job per attack downloads that attack's
experiment, builds two images (`ci/atlas/eval.Dockerfile`: Python 3.7 with the authors'
evaluation dependencies; `ci/atlas/tf.Dockerfile`: TensorFlow 2.3.0, keras 2.4.3 and the ATLAS
README's pins), runs everything third-party with `--network none`, and then:

- runs the authors' `evaluate.py` in every released experiment folder;
- re-runs `model.h5` with `atlas.py` (`DO_TRAINING = False`) and diffs the fresh outputs against
  the released ones (`benchmarks/atlas_rerun.py`);
- runs REVENANT on each test host and scores four methods with the same `evaluate.py`
  (`benchmarks/bench_atlas.py`).

The combine job probes the ATLASv2 link (HEAD only) and writes `atlas_repro.json` and
`atlas_revenant.json`; it fails if any `evaluate.py` run fails outside the allowlist (only
`M4_h1`), if fewer than 10 attacks were scored, if the event macro is more than 1e-4 from the
paper, or if the model re-run block is missing. Run 37090608948 took 2.4-22 minutes per attack
(S2, the largest log, is the slowest). Expected:

```text
evaluate.py re-run on released outputs: {'n_attacks': 10, 'entity_macro': {... 'f1': 0.9132}, 'event_macro': {'precision': 0.9988, 'recall': 0.9988, 'f1': 0.9988}, ...}
Table 4 vs re-run: identical for 0 attacks
model re-run: {'test_graphs': 16, 'atlas_py_ok': 16, 'graph_words_identical': 16, 'predicted_words_identical': 15, ...}
revenant           n=10 entity macro {'precision': 0.4363, 'recall': 0.8427, 'f1': 0.5562} event macro {... 'f1': 0.5735}
```

## 5. Live auditd capture

Runs in CI (`live-auditd` job). It needs root and auditd, so it is meant for an ephemeral
runner only: `bash ci/live/capture_auditd.sh live-out && python ci/live/check_live.py live-out`.
The committed `results/live_auditd.json` is the `live_result.json` of a named CI run.
