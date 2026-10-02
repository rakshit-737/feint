# Reproduction: Sharafaldin, Habibi Lashkari & Ghorbani, ICISSP 2018, Table 4

Assumptions:

- union of the Table 3 per-label feature selections (23 features)
- corrected CIC-IDS2017 (Engelen et al. 2021), 5 day files, '- Attempted' flows relabelled benign, duplicates kept, rows with inf/NaN dropped
- stratified 70/30 split (the paper does not report its split)
- scikit-learn defaults; ID3 = DecisionTree(criterion='entropy'); KNN and MLP on standardised features (not stated in the paper)
- KNN trained on a stratified subsample of at most 300000 flows (runtime)
- weighted multi-class precision / recall / F1 over the 16 labels
- 'QDA (reg_param=1e-3)' deviates from the defaults (covariance regulariser); the default fit is reported as well

| model | paper Pr / Rc / F1 | ours Pr / Rc / F1 | ours time (s) |
|---|---|---|---|
| KNN | 0.96 / 0.96 / 0.96 | 0.993 / 0.993 / 0.993 | 344.4 |
| RF | 0.98 / 0.97 / 0.97 | 0.995 / 0.995 / 0.995 | 163.6 |
| ID3 | 0.98 / 0.98 / 0.98 | 0.995 / 0.995 / 0.995 | 34.3 |
| Adaboost | 0.77 / 0.84 / 0.77 | 0.949 / 0.960 / 0.954 | 486.2 |
| MLP | 0.77 / 0.83 / 0.76 | 0.994 / 0.994 / 0.994 | 145.7 |
| Naive-Bayes | 0.88 / 0.04 / 0.04 | 0.866 / 0.321 / 0.365 | 9.8 |
| QDA | 0.97 / 0.88 / 0.92 | failed to fit: The covariance matrix of class Botnet is not full rank. Increase the value of `reg_param` to reduce the collinearity. | - |
| QDA (reg_param=1e-3) | 0.97 / 0.88 / 0.92 | failed to fit: The covariance matrix of class Heartbleed is not full rank. When using `solver='svd'` the number of samples in each class should be more than the number of features, but class Heartbleed has 8 samples | - |
