PY ?= python
export FEINT_DATA ?= $(CURDIR)/data

.PHONY: install test lint data bench bench-cic bench-unsw demo serve clean

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check feint tests scripts

data:
	$(PY) scripts/download_unsw_nb15.py
	$(PY) scripts/download_cicids2017.py

bench: bench-unsw bench-cic

bench-unsw:
	$(PY) -m feint run --data unsw_nb15 --out results/unsw_nb15 --save-model

bench-cic:
	$(PY) -m feint run --data cicids2017 --out results/cicids2017 --save-model

demo:
	$(PY) -m feint run --quick --n 3000 --out results/demo

serve:
	$(PY) -m feint serve --model results/cicids2017/model.joblib

clean:
	rm -rf results/demo .pytest_cache .ruff_cache build *.egg-info
