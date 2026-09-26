# `make` is optional: every target is a single command you can run directly.
.PHONY: install test test-real lint data bench figures demo demo-real serve clean

PY ?= python

install:
	$(PY) -m pip install -e ".[dev,evtx,api,bench]"

test:
	$(PY) -m pytest -q

test-real:
	$(PY) -m pytest -q -m realdata

lint:
	$(PY) -m ruff check src tests benchmarks scripts

data:
	$(PY) scripts/download_data.py

bench:
	cd benchmarks && $(PY) bench_edges.py && $(PY) bench_stories.py && $(PY) bench_antiforensics.py && $(PY) bench_scale.py && $(PY) make_figures.py

figures:
	cd benchmarks && $(PY) make_figures.py

demo:
	PYTHONPATH=src $(PY) -m revenant.cli demo --scenario intrusion

demo-real:
	PYTHONPATH=src $(PY) -m revenant.cli analyze tests/fixtures/otrf_psexec_lsa_secrets.jsonl --top 3

serve:
	REVENANT_EVIDENCE_ROOT=tests/fixtures PYTHONPATH=src $(PY) -m revenant.cli serve

clean:
	rm -rf .pytest_cache .ruff_cache **/__pycache__ src/**/__pycache__
