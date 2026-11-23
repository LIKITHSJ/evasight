# Evasight: paper outline

Working title: Do explanations of a network intrusion detector stay stable under realistic evasion?
Write each section in its own file (paper/03_threat_model.md, ...). Plain Markdown; LaTeX at the end.

## 1. Introduction (both)
- Problem: NIDS models are evaded; explanations (SHAP/LIME) are trusted by analysts.
- Question: are explanations stable under constraint-respecting evasion, and can instability flag evasion?
- Contributions (to confirm at the end).

## 2. Related work (both)
- Adversarial ML for NIDS with domain constraints; explainable NIDS; dataset quality studies (Engelen et al.).

## 3. Threat model (Likhith)
- Attacker: controls only its own (forward/source) packets; white-box access to the model; no poisoning.
- Actions: payload padding and inter-packet delay, budget eps relative to the flow's own values.
- Constraints: protocol semantics (flags, ports, protocol fixed), MTU/MSS, flow-meter timeouts.
- Feature controllability: free / derived / fixed (configs/*_controllability.csv).

## 4. Datasets and data quality (Likhith)
- CIC-IDS2017 Improved, CSE-CIC-IDS2018 (original; no improved release exists), UNSW-NB15 (official split).
- Leak-aware splits: conflicting-label vectors dropped, feature dedup, per-class time blocks (CIC), no vector in two partitions.
- Findings: 2018 12-hour clock without AM/PM; header/segment rules hold only for TCP in the Improved release;
  bulk features non-zero in Improved 2017; UNSW split counts (train 107,740 / test 55,005); metadata leakage risk (capture day).

## 5. Attack method (Likhith)
- Perturbation per dataset, derived-feature recompute, validity rules calibrated on clean train data.
- Grid search over (pad, delay), cumulative budget; skip flows whose features cannot be kept consistent.

## 6. Models and explanations (Sharath)
- Calibrated XGBoost baselines (+ MLP), SHAP and LIME, stability metrics.

## 7. Results (both)
- Evasion per dataset and class (eps 0.1 / 1.0): 2017 99, 2018 1,364, UNSW 1,002 at eps 1.0.
- Explanation stability and instability-based detection (pending).

## 8. Limitations and conclusion (both)
- Summary-statistic features only (no packet traces); conservative choices that lower evasion; tiny classes.
