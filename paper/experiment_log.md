# Evasight experiment log

This log records experiments and evidence discovered during maintenance. Documentation
updates are not experiments. Dates are included only when present in a repository record or
provided run description; artifact modification times are not treated as experiment dates.

## 2026-11-23 — Project status: XGBoost and attacks

- **Evidence:** `docs/STATUS.md`, README and model JSON artifacts.
- **Reported scope:** leak-aware splits, XGBoost baselines and perturbation attacks for all
  three datasets.
- **Status:** historical project-reported benchmark. Model files confirm features and best
  iterations, but not all test metrics. Different calibrated numbers appear in the status
  records and the later supplied metrics; reconcile run versions before final reporting.
- **Artifact paths:** `artifacts/xgb_improved.json`,
  `artifacts/xgb_cic2018_improved.json`, `artifacts/xgb_unsw.json` and matching calibration
  joblibs. Files are local or repository artifacts; no new files were created by this update.
- **Source revision:** current repository `HEAD` is `1b31bd1`; no matching per-run source
  commit is recorded in the artifacts.

## Date not recorded — CIC-IDS2017 MLP stratified smoke test

- **Evidence:** run values supplied in the research brief and a local smoke checkpoint.
- **Scope:** stratified 20,000/5,000/5,000 train/validation/test sample; 79 numeric features;
  two epochs; seed 42; batch size 2,048; shuffle buffer 8,192.
- **Outcome:** best epoch 2; validation BCE 0.346835; metrics recorded in
  `experimental_results.md`.
- **Classification:** preliminary smoke test, not a full-dataset benchmark.
- **Artifacts:** ignored local checkpoint/preprocessor under `artifacts/mlp_smoke_models/`.
- **Source revision and exact run command:** not embedded in the checkpoint or supplied run
  record.

## Date not recorded — Six-example MLP SHAP/LIME smoke test

- **Evidence:** supplied experiment notes and local
  `artifacts/mlp_smoke_explanations/mlp_cic2017_smoke_metadata.json`.
- **Scope:** six CIC-IDS2017 smoke-checkpoint observations, 79 features; SHAP
  GradientExplainer (100-row training background, 128 samples); LIME Tabular (1,000
  samples per observation).
- **Outcome:** both explainers returned results; no stability or inferential conclusion.
- **Classification:** exploratory software/behavior check only, using the MLP smoke
  checkpoint, not the completed full MLP checkpoint.
- **Source revision and exact run command:** not recorded.

## Date not recorded — Explainer functionality checks

- **Evidence:** user-supplied experiment record; no run manifests located.
- **Scope:** SHAP TreeExplainer on XGBoost, SHAP GradientExplainer on PyTorch, and LIME
  on a synthetic prediction function, a trained synthetic XGBoost model and the Evasight
  MLP smoke checkpoint.
- **Outcome:** the explainers generated outputs in the reported environment. This validates
  basic functionality only, not stability, correctness under perturbation or model fidelity.
- **Environment:** SHAP 0.51.0 and LIME 0.2.0.1 were reported; SHAP used a local MAPLE
  import guard as described in `reproducibility.md`.

## 2026-11-28 — Completed full CIC-IDS2017 MLP baseline

- **Evidence:** the complete training terminal output was supplied directly to the research
  assistant, and its reported configuration/results match the ignored local checkpoint
  `artifacts/mlp_full_models/mlp_cic2017_improved.pt` and preprocessor metadata.
- **Classification:** completed full CIC-IDS2017 MLP baseline. This is not a robustness
  experiment, and independent reproduction is not complete.
- **Partitions:** train 1,270,642; validation 267,435; test 274,132 rows. Full training and
  validation partition sizes were verified; the test partition size is also recorded.
- **Configuration:** architecture 79 → 128 → 64 → 32 → 1; learning rate 0.001; batch size
  4,096; maximum 50 epochs; patience 5; seed 42; CPU, four threads; shuffle buffer 65,536;
  dropout 0.2.
- **Outcome:** best epoch 13; best validation BCE 0.08116819488130779; training stopped at
  epoch 18. Raw and isotonic-calibrated test metrics are in `experimental_results.md`.
- **Artifacts:** `artifacts/mlp_full_models/mlp_cic2017_improved.pt` and
  `artifacts/mlp_full_models/mlp_cic2017_improved_preprocessor.joblib`; ignored/local, do
  not commit.
- **Remaining provenance:** identify the source commit, associate exact dataset hashes with
  the run, and archive the complete execution log to enable stronger independent
  reproducibility. The checkpoint has no source hash or dataset checksum association.
- **Environment note:** loading the preprocessor in the inspected interpreter emitted
  scikit-learn version warnings (serialized 1.9.1, current interpreter 1.4.2).

## 2026-11-28 — Completed full CSE-CIC-IDS2018 Improved MLP baseline

- **Evidence:** full 39-epoch training/validation history and final results supplied in the
  experiment record; local checkpoint metadata matches the reported configuration, selected
  epoch, validation loss, features and test metrics. Category supports were counted from
  `data/processed/cic_ids2018_improved/test.parquet`.
- **Classification:** completed full-data detection baseline, not a robustness result or an
  independent reproduction.
- **Partitions:** 5,607,932 train / 1,167,746 validation / 1,210,959 test rows
  (7,986,637 total). The complete training partition was used; validation was used for early
  stopping and isotonic calibration, with test held out for final evaluation.
- **Configuration:** 79 numerical inputs; architecture 79 → 128 → 64 → 32 → 1; Adam;
  BCEWithLogitsLoss; learning rate 0.001; batch 4,096; max 50 epochs; patience 5; seed 42;
  CPU, four threads; shuffle buffer 65,536; dropout 0.2.
- **Outcome:** best epoch 34; best validation BCE 0.0017749854158630768; stopped at epoch
  39. The supplied epoch history is recorded in `experimental_results.md`.
- **Test result:** raw/calibrated ROC-AUC 0.9998328333/0.9996433201; PR-AUC
  0.9998393043/0.9996211737; Brier 0.0007066405/0.0005755883; ECE
  0.0011599217/0.0003442207; TPR@1% FPR 0.9993081023/0.9993067597; benign FPR@0.5
  0.0000611964/0.0001325922. Calibration improves Brier/ECE but slightly lowers AUCs and
  increases benign FPR at 0.5; details and per-category results are in the evidence ledger.
- **Category findings:** the test partition has 686,315 benign rows and 524,644 attack
  rows. Dropbox Download has 0/13 recall; DoS Slowloris recall is about 73.2% on 1,274
  rows; Web Attack - SQL recall is 4/6. These are weaknesses requiring follow-up; the tiny
  SQL support makes its recall highly uncertain.
- **Derived error counts:** multiplying the stored per-category recalls by the test supports
  gives 852 approximate raw attack false negatives and 685 calibrated false negatives.
  Slowloris (341 raw misses) and NMAP Portscan (427) account for 768/852, about 90%, of
  raw misses. The FPR metrics imply about 42 raw and 91 calibrated benign false positives
  at threshold 0.5. Calibration's reduction in estimated attack misses therefore comes
  with more benign false positives; it is not a universal detection improvement.
- **Count verification:** category supports were read from the actual CIC-IDS2018 test
  Parquet and sum to 1,210,959. The checkpoint stores per-category recalls, but no
  prediction arrays or confusion matrices were available; missed/false-positive counts are
  derived estimates, not direct confusion-matrix counts. Detailed category values are in
  `experimental_results.md`.
- **Operating-point caveat:** attacks are 43.32% of this test partition. ROC-AUC measures
  ranking across thresholds; the fixed-0.5 confusion trade-off and rare-category
  uncertainty must be considered separately for operational effectiveness.
- **Artifacts:** `artifacts/mlp_cic2018_models/mlp_cic2018_improved.pt` (89,859 bytes) and
  `artifacts/mlp_cic2018_models/mlp_cic2018_improved_preprocessor.joblib` (6,034 bytes);
  local generated artifacts, do not commit.
- **Environment:** the run record identifies Windows, Smart App Control enabled, and the
  separate `evasight-sac-test` environment. Repository `.venv` package versions and the
  previously reported run-environment package versions are distinguished in
  `reproducibility.md`; exact runtime binding still needs a lock/freeze record.
- **Remaining provenance and science:** source commit, dataset-hash association and an
  archived original terminal log are missing. The high benchmark AUCs do not establish
  adversarial robustness; test feature ablation and the `fwd_init_win_bytes` shortcut.
  Full-model SHAP/LIME and adversarial explanation-stability experiments are pending.

## 2026-11-28 — CIC-IDS2018 MLP exact reproducibility / deterministic rerun

- **Classification:** repeatability experiment using the same dataset partitions, code path,
  random seed and training configuration as the completed CIC-IDS2018 baseline. This is
  not a new independent benchmark, a separate architecture or a third independent trial.
- **Partitions/configuration:** 5,607,932 train / 1,167,746 validation / 1,210,959 test
  (7,986,637 total); 79 numerical features, zero categorical features; hidden layers
  128/64/32, ReLU, dropout 0.2, one-logit output; learning rate 0.001; batch 4,096; max 50
  epochs; patience 5; seed 42; four CPU threads; shuffle buffer 65,536.
- **Repeatability:** the supplied run records identical epoch-by-epoch training and
  validation BCE histories. Both selected epoch 34, best validation BCE
  0.0017749854158630768, and stopped after epoch 39.
- **Evaluation:** exact raw/calibrated metrics match the original baseline: ROC-AUC
  0.9998328332671429/0.9996433201263473; PR-AUC
  0.9998393042699056/0.9996211736990037; Brier
  0.0007066404796205461/0.0005755882593803108; ECE
  0.0011599216779981903/0.000344220710041977; TPR@1% FPR
  0.999308102256006/0.9993067596949815; benign FPR@0.5
  0.00006119638941302463/0.00013259217706155336. Calibration improves Brier/ECE while
  slightly reducing AUCs and increasing benign FPR, not every metric.
- **Artifact verification:** original and rerun checkpoints have identical SHA-256
  `B83FE5B80B2F20258C21A627A7B67B05D3FCB096618F09B2B89F2EF440425D4C`; original and
  rerun preprocessors have identical SHA-256
  `889432D5C95D19F9D36FEBC7CD9C08515D65A69AD43DF8BDE6072D933F182913`. All four file
  hashes were recomputed locally. Paths and file-specific values are in
  `experimental_results.md`.
- **Interpretation:** byte-identical saved artifacts and identical BCE histories support
  deterministic repeatability under this tested setup. This does not establish
  cross-platform reproducibility, independent benchmark performance, or validate the
  explanation-instability hypothesis.
- **Remaining limitations:** only seed 42 was tested; multi-seed variability is unknown.
  Partition counts were verified, but source dataset files were not checked against
  cryptographic hashes. A Git commit identifier and complete software-environment
  fingerprint are not independently associated with both runs. No new adversarial or
  explanation-stability experiment was performed.

## 2026-11-28 — Research documentation maintenance

- Created/updated the integrated manuscript and evidence ledgers.
- Verified local split sizes, tracked configuration row counts, model best-iteration
  attributes, MLP checkpoint metadata, and the relevant official publication/dataset pages.
- No model training, perturbation experiment or explanation experiment was run in this
  documentation pass.
