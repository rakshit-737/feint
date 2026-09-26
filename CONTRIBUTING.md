# Contributing to FEINT

Thanks for your interest. FEINT is a research codebase: the honesty of the *evaluation*
matters more than feature count, so contributions are judged first on whether they keep the
robustness numbers honest.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest -q                                 # a few minutes, no datasets needed
python -m ruff check feint tests scripts
```

Tests use tiny committed fixtures (`tests/fixtures/`). Tests that need the real datasets are
marked `@pytest.mark.realdata` and skip automatically when the data is absent. To run them:

```bash
python scripts/download_unsw_nb15.py
python scripts/download_cicids2017.py
FEINT_DATA=./data python -m pytest -q -m realdata
```

## Ground rules

- **Never commit datasets, pcaps or model bundles.** Add a download script with a SHA-256
  instead. Committed artefacts must be small (< 500 KB) derived results.
- **No live malware, no exploit code, no scanning.** FEINT attacks *feature vectors* of public
  datasets against models you train locally.
- **Attacks must not get weaker.** If you change `feint/attack.py`, show that the robustness
  curves of the undefended models did not go *up*: a weaker attack makes every defence look
  better.
- **Constraint changes need a justification.** Any edit to `feint/schema.py` must explain, in the
  docstring or an ADR, why the attacker can (or cannot) control that feature.
- **Report honestly.** Numbers in the README must come from `results/*/report.json` produced by the
  committed code, together with the command that produced them.

## Commit style

Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `ci:`, `data:`, `perf:`, `refactor:`),
one logical change per commit. Hard-to-reverse design decisions get an ADR in `docs/adr/`.

## Pull requests

1. Open an issue first for anything larger than a bug fix.
2. Add or update tests; `pytest` and `ruff` must pass in CI.
3. If results change, regenerate the affected `results/<dataset>/` directory and update the
   README tables in the same PR.
