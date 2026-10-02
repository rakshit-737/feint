# Reproduction: Sharafaldin, Habibi Lashkari & Ghorbani, ICISSP 2018, Table 4

Assumptions:

- union of the Table 3 per-label feature selections (23 features)
- all 8 MachineLearningCVE CSVs, duplicates kept, rows with inf/NaN dropped
- stratified 70/30 split (the paper does not report its split)
- scikit-learn defaults; ID3 = DecisionTree(criterion='entropy'); KNN and MLP on standardised features (not stated in the paper)
- KNN trained on a stratified subsample of at most 300000 flows (runtime)
- weighted multi-class precision / recall / F1 over the 15 labels
- 'QDA (reg_param=1e-3)' deviates from the defaults (covariance regulariser); the default fit is reported as well

| model | paper Pr / Rc / F1 | ours Pr / Rc / F1 | ours time (s) |
|---|---|---|---|
| KNN | 0.96 / 0.96 / 0.96 | 0.995 / 0.995 / 0.995 | 463.4 |
| RF | 0.98 / 0.97 / 0.97 | 0.998 / 0.999 / 0.999 | 194.7 |
| ID3 | 0.98 / 0.98 / 0.98 | 0.998 / 0.998 / 0.998 | 49.8 |
| Adaboost | 0.77 / 0.84 / 0.77 | 0.895 / 0.904 / 0.888 | 682.5 |
| MLP | 0.77 / 0.83 / 0.76 | 0.982 / 0.982 / 0.981 | 1224.0 |
| Naive-Bayes | 0.88 / 0.04 / 0.04 | 0.866 / 0.106 / 0.141 | 13.4 |
| QDA | 0.97 / 0.88 / 0.92 | failed to fit: The covariance matrix of class BENIGN is not full rank. Increase the value of `reg_param` to reduce the collinearity. | - |
| QDA (reg_param=1e-3) | 0.97 / 0.88 / 0.92 | 0.940 / 0.834 / 0.869 | 18.2 |
