.PHONY: install test demo lint clean

PY ?= python

install:
	$(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest -q

demo:
	PYTHONPATH=src $(PY) -m revenant.cli demo --scenario intrusion

demo-timestomp:
	PYTHONPATH=src $(PY) -m revenant.cli demo --scenario timestomp

scenarios:
	PYTHONPATH=src $(PY) -m revenant.cli scenarios

clean:
	rm -rf .pytest_cache **/__pycache__ src/**/__pycache__
