PY ?= python

.PHONY: install test demo clean

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

demo:
	$(PY) -m feint run --out results

clean:
	rm -rf results .pytest_cache build *.egg-info
