# Datasets

| dataset | what we use | size | licence / terms | citation |
|---|---|---|---|---|
| **CIC-IDS2017** | `MachineLearningCSV.zip` (CICFlowMeter features, 8 day files, 2,830,743 flows, 14 attack classes). 11 columns mapped into the schema; 530,897 exact duplicates dropped; 10 % per-class sample with a floor of 5,000 (rare classes kept whole) = 253,259 flows, 25.7 % attacks; stratified 70/30 split. | 235 MB zip, 885 MB CSV | Free for research with citation, per the Canadian Institute for Cybersecurity (UNB) | Sharafaldin, Lashkari, Ghorbani. *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.* ICISSP 2018 |
| **UNSW-NB15** | Official partition: training set 175,341 flows, testing set 82,332 flows (10 classes). 22 features (14 direct, 2 protocol flags, 6 derived). | 48 MB | Free for academic research with citation, per UNSW Canberra Cyber | Moustafa, Slay. *UNSW-NB15: a comprehensive data set for network intrusion detection systems.* MilCIS 2015 |

Official hosts gate downloads behind forms, so `scripts/download_*.py` fetch third-party
mirrors from the Hugging Face Hub (not checked byte-for-byte against the official archives; row
counts match the official releases: 2,830,743 CIC flows, 175,341 / 82,332 UNSW flows), resume
interrupted transfers and **verify SHA-256** against the pinned hashes ([ADR 0006](adr/0006-data-sources-sampling-and-splits.md)). Datasets are
never committed; `tests/fixtures/` holds ~930 sampled rows for CI.

See also [ADR 0006](adr/0006-data-sources-sampling-and-splits.md).
