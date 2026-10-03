# Contributing to REVENANT

Thanks for helping. REVENANT is a lab-only, defensive DFIR tool. Contributions
must keep it that way: no exploit code, no live malware, and nothing that
scans or touches systems you are not authorised to analyse.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev,evtx,api]"
python -m pytest -q                                # fast suite, uses committed fixtures
python -m ruff check src tests benchmarks scripts
```

Real-data tests and benchmarks need the public corpora:

```bash
python scripts/download_data.py                    # ~86 MB compressed, checksum-verified
python -m pytest -m realdata
python benchmarks/bench_edges.py && python benchmarks/bench_stories.py
python benchmarks/bench_antiforensics.py && python benchmarks/bench_scale.py
python benchmarks/make_figures.py
```

## Ground rules

- **Every causal claim comes from a named rule.** A new rule needs a unit
  test, and if it touches process lineage, a before/after run of
  `benchmarks/bench_edges.py`. Report the numbers in the PR.
- **Never hide evidence.** A parser that cannot interpret a record counts it
  (`LoadStats.unmapped` / `bad_rows` / `unreadable_files`). It never drops it
  silently.
- **Heuristics are generic.** ATT&CK patterns in `attack.py` must be public,
  generic detection logic, not tuned to a benchmark capture. Say where a
  pattern comes from in the PR.
- **No datasets in git.** Add a pinned, checksummed entry to the downloader
  instead. Fixtures must be tiny, and either synthetic or permissively
  licensed with attribution in `docs/datasets.md`.
- Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`,
  `ci:`), small and focused.
- Significant design changes get an ADR in `docs/adr/`.

## Reporting security issues

See `SECURITY.md`. Please do not open public issues for vulnerabilities.
