# ADR 0006: Data sources, sampling and splits

- Status: accepted
- Date: 2026-09-26

## Context

CIC-IDS2017 (UNB) and UNSW-NB15 (UNSW Canberra) are the two most-cited flow datasets.
The official hosts gate downloads behind forms or SharePoint, which cannot be scripted.
CIC-IDS2017 has 2.83 M flows, heavy class imbalance and many exact duplicates, which leak
between random train/test splits and inflate reported accuracy.

## Decision

- Download third-party mirrors from the Hugging Face Hub and verify SHA-256
  (`scripts/download_*.py`); cite the official source and licence in the README.
- CIC-IDS2017: map 11 CICFlowMeter columns into the schema, drop non-finite rows, drop exact
  duplicate (feature vector, label) rows *before* splitting, then sample 10 % per class while
  keeping every class with fewer than 5,000 flows whole (Heartbleed, Infiltration, SQL
  injection, XSS, Bot, ...). Stratified 70/30 split. A second, *temporal* split trains on
  Monday-Wednesday and tests on Thursday-Friday to expose unseen attack families.
- UNSW-NB15: use the official training (175,341) / testing (82,332) partition unchanged. The
  mirror swaps the two file names; the script restores them (verified by row count and hash).

## Consequences

- Our CIC numbers are on de-duplicated data and are expected to be slightly *lower* than
  papers that split with duplicates. Prevalence in the sample differs from the raw capture,
  so we also report precision at fixed 1 % and 0.1 % attack base rates.
- Everything is reproducible from the seed and the checksummed files.
