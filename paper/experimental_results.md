# Evasight experimental results ledger

**Status:** living ledger; results below are not final benchmark claims unless explicitly
marked as artifact-backed and reproducibility-complete. This file distinguishes supplied
historical reports, tracked project records and local ignored artifacts.

## 1. Detection-model evidence

### 1.1 XGBoost metrics supplied as historical results

The following numerical metrics were supplied in the research brief as earlier experiment
outputs. The local XGBoost model files confirm the feature counts and `best_iteration`
attributes shown below, but do not store the full test metrics. The metrics are therefore
**previously reported, not independently reproduced or accepted as final results**.

| Dataset | Best iteration | Raw ROC-AUC | Raw PR-AUC | Raw Brier | Raw ECE | Raw TPR@1% FPR | Calibrated ROC-AUC | Calibrated PR-AUC | Calibrated Brier | Benign FPR@0.5 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CIC-IDS2017 Improved | 283 | 1.00000 | 0.99999 | 0.00032 | 0.00048 | 0.9999 | 0.99937 | 0.99902 | Not supplied | 0.0042% |
| CSE-CIC-IDS2018 Improved | 306 | 1.00000 | 1.00000 | 0.00031 | 0.00029 | Not supplied | Not supplied | Not supplied | 0.00033 | 0.0284% |
| UNSW-NB15 | 475 | 0.96457 | 0.94728 | 0.11533 | 0.12676 | 0.6939 | 0.96395 | 0.94058 | Not supplied | 25.4233% |

The historical report also gives CSE-CIC-IDS2018 Slowloris recall 0.8187 and Dropbox
Download recall 0/13. Very small support makes the latter descriptive only.

### 1.2 What tracked records independently confirm

The local model JSON files report these XGBoost attributes:

| File | Features | Best iteration | Stored best validation score |
|---|---:|---:|---:|
| `artifacts/xgb_improved.json` | 79 | 283 | 0.0003188098 |
| `artifacts/xgb_cic2018_improved.json` | 79 | 306 | 0.0001688417 |
| `artifacts/xgb_unsw.json` | 42 | 475 | 0.13521797 |

These values corroborate model-selection metadata, not the test metrics above. The code
uses validation log loss for early stopping.

The earlier `docs/STATUS.md`/README baseline table reports calibrated AUCs and benign
false-positive rates of 0.9988/0.002% for CIC-IDS2017, 1.0000/0.0077% for CSE-CIC-IDS2018,
and 0.9661/25.4% for UNSW-NB15. These differ from the separately supplied historical
calibration metrics. The exact model/data revision behind each result has not been reconciled.
Do not silently substitute one set for the other; version each run and verify the split and
calibration outputs before a final comparison.

### 1.3 Previously reported attack outcomes

`docs/STATUS.md` reports these attack outcomes on the leak-aware test partitions. Evasion
counts are among attacks detected before perturbation; budgets are cumulative.

| Dataset | Detected attacks in denominator | Evasions at ε=0.1 | Evasions at ε=1.0 |
|---|---:|---:|---:|
| CIC-IDS2017 Improved | 60,083 | 39 (0.06%) | 93 (0.15%) |
| CSE-CIC-IDS2018 Improved | 524,539 | 23 (0.00% when rounded to 2 decimals) | 197 (0.04%) |
| UNSW-NB15 | 18,335 | 382 (2.08%) | 1,002 (5.46%) |

These are tracked status-record results, not independently rerun during this documentation
update. The development experiment in `docs/audit/attack_dev_results.md` used a random
split and a throwaway model and is explicitly **not a paper result**. The report
`docs/audit/findings_2026-11-19.md` is also development analysis; it warns that observed
SHAP changes may track attack-likeness rather than evasion specificity.

## 2. MLP evidence

### 2.1 CIC-IDS2017 stratified smoke test

**Classification: preliminary smoke test; not a full-dataset benchmark.** The supplied
run description and local checkpoint metadata identify 20,000 training, 5,000 validation
and 5,000 test examples sampled/stratified by class. The sampled partitions are not the
preserved full-dataset partitions.

| Configuration | Value |
|---|---|
| Features | 79 numerical; 0 categorical |
| Learning rate / dropout | 0.001 / 0.2 |
| Batch size | 2,048 |
| Maximum epochs / patience | 2 / 2 |
| Seed / CPU threads | 42 / 4 |
| Shuffle buffer | 8,192 |
| Best epoch | 2 |

| Epoch | Training BCE | Validation BCE |
|---:|---:|---:|
| 1 | 0.613723 | 0.548301 |
| 2 | 0.469437 | 0.346835 |

| Test metric | Raw | Isotonic calibrated |
|---|---:|---:|
| ROC-AUC | 0.970264 | 0.975514 |
| PR-AUC | 0.954773 | 0.944538 |
| Brier score | 0.089077 | 0.037351 |
| ECE | 0.234010 | 0.020390 |
| TPR@1% FPR | 0.749091 | 0.762545 |
| Benign FPR@0.5 | 0.7436% | 1.6667% |

The supplied notes report low or zero recall for several attack categories at threshold 0.5.
Treat the observation as preliminary; sample-level category support is not recorded here.

Local artifacts, ignored by Git:

- `artifacts/mlp_smoke_models/mlp_cic2017_improved.pt`
- `artifacts/mlp_smoke_models/mlp_cic2017_improved_preprocessor.joblib`

### 2.2 Completed CIC-IDS2017 full MLP baseline

**Classification: completed full CIC-IDS2017 MLP baseline, supported by user-supplied
execution evidence and matching local checkpoint metadata.** The full training run
completed successfully on 28 November 2026. Its terminal output was supplied directly to
the research assistant, and the checkpoint at
`artifacts/mlp_full_models/mlp_cic2017_improved.pt` and preprocessor are present locally.
The run used the full verified CIC-IDS2017 partitions:

| Partition | Rows |
|---|---:|
| Train | 1,270,642 |
| Validation | 267,435 |
| Test | 274,132 |

| Configuration | Value |
|---|---|
| Architecture | 79 → 128 → 64 → 32 → 1 |
| Learning rate | 0.001 |
| Batch size | 4,096 |
| Maximum epochs | 50 |
| Patience | 5 |
| Seed | 42 |
| Device / CPU threads | CPU / 4 |
| Shuffle buffer | 65,536 |
| Dropout | 0.2 |
| Best epoch | 13 |
| Best validation BCE | 0.08116819488130779 |
| Training stopped | Epoch 18 |

The terminal output reports the following untouched test-partition metrics after selecting
the best epoch and fitting isotonic calibration on validation probabilities:

| Test metric | Raw | Isotonic calibrated |
|---|---:|---:|
| ROC-AUC | 0.9995144622 | 0.9994083069 |
| PR-AUC | 0.9988095222 | 0.9982143313 |
| Brier score | 0.0028689960 | 0.0031982549 |
| ECE | 0.0024555096 | 0.0077651668 |
| TPR@1% FPR | 0.9944286922 | 0.9943791927 |
| Benign FPR@0.5 (fraction) | 0.0005705654 | 0.0003834948 |

At raw probability threshold 0.5, the checkpoint reports recall 0.3257 for DoS
Slowhttptest, 0.5181 for DoS Slowloris, 0 for Heartbleed, 0 for Infiltration, 0 for
Web Attack - SQL Injection, and 0.6667 for Web Attack - XSS. The current processed
CIC-IDS2017 test file has 261, 579, 2, 6, 2 and 3 examples in those categories,
respectively, but the checkpoint does not store a test-partition hash. These support counts
may not identify the checkpoint's exact evaluation subset. If they do correspond, the tiny
supports make category recall highly uncertain.

**Provenance qualification:** the checkpoint demonstrates that a CIC-IDS2017 artifact with
full-run configuration and test metrics exists locally; the user-supplied execution output
and verified partition sizes establish that this was a completed full-partition baseline.
This is a detection baseline, not a robustness or explanation-stability experiment, and it is
not an independently reproduced result. The terminal output has not been archived with the
repository, and the run lacks a source commit identifier and an explicit association to
dataset checksums. Preserve and archive those provenance items before claiming stronger
independent reproducibility. The model and preprocessor remain ignored local artifacts and
must not be committed.

### 2.3 Completed CSE-CIC-IDS2018 Improved full MLP baseline

**Classification: completed full CSE-CIC-IDS2018 Improved MLP baseline.** The supplied
execution record reports successful training on the complete training partition and final
evaluation on the reserved test partition. The locally inspected checkpoint metadata matches
the reported architecture, best epoch, validation loss, training configuration and test
metrics. The actual test Parquet was also inspected to count each attack category.

| Partition | Rows |
|---|---:|
| Train | 5,607,932 |
| Validation | 1,167,746 |
| Test | 1,210,959 |
| Total | 7,986,637 |

| Configuration | Value |
|---|---|
| Architecture | 79 → 128 → 64 → 32 → 1 |
| Optimizer / loss / class weighting | Adam / BCEWithLogitsLoss / none |
| Learning rate | 0.001 |
| Batch size | 4,096 |
| Maximum epochs / patience | 50 / 5 |
| Seed | 42 |
| Device / CPU threads | CPU / 4 |
| Shuffle buffer | 65,536 |
| Dropout | 0.2 |
| Calibration | IsotonicRegression fitted on validation probabilities |
| Best epoch | 34 |
| Best validation BCE | 0.0017749854158630768 |
| Training stopped | Epoch 39 |

The supplied epoch history is retained below; epoch 34 was selected by validation BCE.

| Epoch | Training BCE | Validation BCE |
|---:|---:|---:|
| 1 | 0.048008 | 0.854736 |
| 2 | 0.015988 | 0.267352 |
| 3 | 0.009170 | 0.354305 |
| 4 | 0.006270 | 0.549060 |
| 5 | 0.004889 | 0.336142 |
| 6 | 0.004136 | 0.110540 |
| 7 | 0.003288 | 0.117147 |
| 8 | 0.002771 | 0.106552 |
| 9 | 0.002459 | 0.148464 |
| 10 | 0.002150 | 0.106476 |
| 11 | 0.001897 | 0.142876 |
| 12 | 0.001805 | 0.404926 |
| 13 | 0.001724 | 0.041089 |
| 14 | 0.001586 | 0.254326 |
| 15 | 0.001417 | 0.025913 |
| 16 | 0.001329 | 0.018619 |
| 17 | 0.001222 | 0.037084 |
| 18 | 0.001183 | 0.011843 |
| 19 | 0.001080 | 0.007139 |
| 20 | 0.001002 | 0.007742 |
| 21 | 0.001025 | 0.005728 |
| 22 | 0.000958 | 0.004103 |
| 23 | 0.000945 | 0.011237 |
| 24 | 0.000888 | 0.003376 |
| 25 | 0.000948 | 0.006967 |
| 26 | 0.000918 | 0.008952 |
| 27 | 0.000840 | 0.002782 |
| 28 | 0.000810 | 0.004840 |
| 29 | 0.000848 | 0.003387 |
| 30 | 0.000883 | 0.002930 |
| 31 | 0.000779 | 0.002570 |
| 32 | 0.000808 | 0.002069 |
| 33 | 0.000751 | 0.003054 |
| 34 | 0.000728 | 0.001775 |
| 35 | 0.000708 | 0.002701 |
| 36 | 0.000668 | 0.002706 |
| 37 | 0.000735 | 0.002660 |
| 38 | 0.000740 | 0.001914 |
| 39 | 0.000739 | 0.002232 |

The selected checkpoint's raw and isotonic-calibrated test metrics are:

| Test metric | Raw | Isotonic calibrated |
|---|---:|---:|
| ROC-AUC | 0.9998328333 | 0.9996433201 |
| PR-AUC | 0.9998393043 | 0.9996211737 |
| Brier score | 0.0007066405 | 0.0005755883 |
| ECE | 0.0011599217 | 0.0003442207 |
| TPR@1% FPR | 0.9993081023 | 0.9993067597 |
| Benign FPR@0.5 | 0.0000611964 (0.00612%) | 0.0001325922 (0.01326%) |

Calibration has a mixed effect: Brier score improves by approximately 18.5% and ECE by
approximately 70.3%; ROC-AUC and PR-AUC decrease slightly, TPR@1% FPR is nearly
unchanged, and benign FPR at the fixed 0.5 threshold increases by about 2.17 times. It is
not accurate to say calibration improved every metric.

Category supports were counted directly from `data/processed/cic_ids2018_improved/test.parquet`
(`attack_cat`). They sum to 1,210,959 observations: 686,315 benign and 524,644 attacks.
Attack missed counts below are derived by multiplying each stored checkpoint recall by
its observed support and rounding to the nearest integer. The product is integer-consistent
for every category, but the checkpoint directory contains no prediction arrays or confusion
matrices to independently confirm the derived counts.

| Category | Test support | Raw recall | Raw missed (approx.) | Isotonic recall | Isotonic missed (approx.) |
|---|---:|---:|---:|---:|---:|
| BENIGN | 686,315 | — | — | — | — |
| Botnet Ares | 21,439 | 0.9981342413 | 40 | 0.9986939689 | 28 |
| DDoS-HOIC | 162,344 | 0.9998952841 | 17 | 0.9999014438 | 16 |
| DDoS-LOIC-HTTP | 43,400 | 1.000000 | 0 | 1.000000 | 0 |
| DDoS-LOIC-UDP | 380 | 1.000000 | 0 | 1.000000 | 0 |
| DoS GoldenEye | 3,384 | 0.9997044917 | 1 | 1.000000 | 0 |
| DoS Hulk | 270,474 | 0.9999704223 | 8 | 0.9999778167 | 6 |
| DoS Slowloris | 1,274 | 0.7323390895 | 341 | 0.7346938776 | 338 |
| Infiltration - Communication Victim Attacker | 31 | 0.9677419355 | 1 | 0.9677419355 | 1 |
| Infiltration - Dropbox Download | 13 | 0.000000 | 13 | 0.000000 | 13 |
| Infiltration - NMAP Portscan | 7,732 | 0.9447749612 | 427 | 0.9637868598 | 280 |
| SSH-BruteForce | 14,130 | 1.000000 | 0 | 1.000000 | 0 |
| Web Attack - Brute Force | 20 | 0.950000 | 1 | 1.000000 | 0 |
| Web Attack - SQL | 6 | 0.6666666667 | 2 | 0.6666666667 | 2 |
| Web Attack - XSS | 17 | 0.9411764706 | 1 | 0.9411764706 | 1 |
| Attack total | 524,644 | — | **852** | — | **685** |
| All test observations | 1,210,959 | — | — | — | — |

Zero recall for Infiltration - Dropbox Download is an unresolved detection weakness; the
test support is 13. DoS Slowloris recall is lower than the other large categories (1,274
records), and Web Attack - SQL recall is 4/6 on a very small support. The latter and other
small-category recalls are descriptive and uncertain, not reliable population estimates.
Infiltration - NMAP Portscan also has a substantial derived miss count (427 of 7,732).
Slowloris and NMAP Portscan together account for 768/852, about 90%, of the derived raw
attack false negatives. Investigate these weaknesses before drawing operational conclusions.

At threshold 0.5, the benign FPR values imply approximately 42 benign false positives raw
and 91 after isotonic calibration (FPR multiplied by the 686,315 benign support). The
derived attack false negatives decrease from 852 to 685, but benign false positives increase.
The CIC-IDS2018 test set is attack-heavy (524,644/1,210,959, about 43.32% attack), so
aggregate metrics reflect this test prevalence. A fixed 0.5 threshold is only one operating
point; threshold choice and the relative cost of false negatives and false positives affect
operational utility. ROC-AUC summarizes ranking across thresholds and does not by itself
establish effective detection at a chosen operating point.

**Scientific qualification:** these exceptionally high benchmark discrimination metrics do
not establish adversarial robustness. The CIC-IDS2018 audit has unresolved version and
row-count discrepancies. `fwd_init_win_bytes` was previously identified as a potentially
strong capture/host-stack shortcut; it is among the 79 selected MLP features. Feature
ablation, capture-specific shortcut analysis, leakage checks and validation of partition
independence are required before interpreting the scores as generalizable detection
performance. No adversarial-evasion or explanation-stability experiment was run for this
MLP baseline.

**Local artifacts (verified, ignored by Git):**

| File | Size |
|---|---:|
| `artifacts/mlp_cic2018_models/mlp_cic2018_improved.pt` | 89,859 bytes |
| `artifacts/mlp_cic2018_models/mlp_cic2018_improved_preprocessor.joblib` | 6,034 bytes |

The checkpoint and preprocessor must not be committed. The source commit and dataset hash
association are not recorded, and the original full terminal log is not present alongside
the artifacts; independent reproduction is not established.

### 2.4 CIC-IDS2018 MLP — Exact Reproducibility / Deterministic Rerun

**Classification: CIC-IDS2018 MLP — Exact Reproducibility / Deterministic Rerun.** This
repeatability experiment used the same CIC-IDS2018 partitions, code path, seed and training
configuration as the original full baseline. It is not a new independent benchmark, a new
architecture, or a third independent trial. The original benchmark results in Section 2.3
remain the primary results and are not replaced by this rerun.

| Partition | Rows |
|---|---:|
| Train | 5,607,932 |
| Validation | 1,167,746 |
| Test | 1,210,959 |
| Total | 7,986,637 |

The rerun used 79 numerical features and no categorical features; hidden layers 128 → 64
→ 32 with ReLU, dropout 0.2 and one output logit. Training used learning rate 0.001,
batch size 4,096, maximum 50 epochs, patience 5, seed 42, four CPU threads and a 65,536
record shuffle buffer. Both executions produced identical epoch-by-epoch training and
validation BCE histories, selected epoch 34 with best validation BCE
0.0017749854158630768, and stopped after epoch 39.

The rerun's test metrics are identical to the original benchmark:

| Test metric | Raw | Isotonic calibrated |
|---|---:|---:|
| ROC-AUC | 0.9998328332671429 | 0.9996433201263473 |
| PR-AUC | 0.9998393042699056 | 0.9996211736990037 |
| Brier score | 0.0007066404796205461 | 0.0005755882593803108 |
| ECE | 0.0011599216779981903 | 0.000344220710041977 |
| TPR@1% FPR | 0.999308102256006 | 0.9993067596949815 |
| Benign FPR@0.5 | 0.00006119638941302463 (0.0061196%) | 0.00013259217706155336 (0.0132592%) |

Isotonic calibration improved Brier score and ECE, but slightly reduced ROC-AUC and PR-AUC
and increased benign FPR at threshold 0.5, consistent with the original benchmark
interpretation.

| Artifact | Original SHA-256 | Rerun SHA-256 | Result |
|---|---|---|---|
| `mlp_cic2018_improved.pt` | `B83FE5B80B2F20258C21A627A7B67B05D3FCB096618F09B2B89F2EF440425D4C` | `B83FE5B80B2F20258C21A627A7B67B05D3FCB096618F09B2B89F2EF440425D4C` | Identical |
| `mlp_cic2018_improved_preprocessor.joblib` | `889432D5C95D19F9D36FEBC7CD9C08515D65A69AD43DF8BDE6072D933F182913` | `889432D5C95D19F9D36FEBC7CD9C08515D65A69AD43DF8BDE6072D933F182913` | Identical |

Original and rerun paths are `artifacts/mlp_cic2018_models/` and
`artifacts/mlp_cic2018_rerun_20261128_models/`, respectively. The four local artifact
hashes were recomputed and match the values above. These byte-identical hashes demonstrate
identity of the saved checkpoint and preprocessor and support deterministic repeatability
under the tested setup. They do not establish cross-platform reproducibility, independent
benchmark performance, or explanation-stability findings. Only seed 42 was tested; multi-
seed variability remains unmeasured. Partition row counts were verified, but source dataset
files were not independently verified by cryptographic checksums. A Git commit identifier
and complete software-environment fingerprint have not been independently associated with
both executions.

## 3. MLP explanation smoke test

The local explanation metadata and supplied run notes describe six observations from the
CIC-IDS2017 MLP **smoke checkpoint**, not the completed full MLP baseline: three benign and
three attack. SHAP used
GradientExplainer, 100 randomly sampled training rows as background and 128 samples;
the output shape was `(6, 79)`. LIME used `LimeTabularExplainer` with 1,000 samples per
observation. Both methods returned explanations. This is a functionality check, not an
estimate of global feature importance or explanation stability.

Top mean-absolute SHAP values reported across those six observations:

| Rank | Feature | Mean absolute SHAP |
|---:|---|---:|
| 1 | `bwd_packet_length_std` | 0.014670 |
| 2 | `bwd_packet_length_mean` | 0.011797 |
| 3 | `fwd_seg_size_min` | 0.011649 |
| 4 | `bwd_rst_flags` | 0.011465 |
| 5 | `packet_length_std` | 0.010986 |
| 6 | `bwd_packet_length_max` | 0.010379 |
| 7 | `packet_length_max` | 0.009882 |
| 8 | `packet_length_variance` | 0.009467 |
| 9 | `packet_length_mean` | 0.008575 |
| 10 | `average_packet_size` | 0.008482 |

| Test index | True class | Raw attack probability |
|---:|---|---:|
| 3261 | Benign | 0.225106 |
| 432 | Benign | 0.207080 |
| 3863 | Benign | 0.264195 |
| 484 | Attack | 0.464265 |
| 3500 | Attack | 0.454472 |
| 4296 | Attack | 0.718900 |

Overlapping SHAP/LIME features reported include `bwd_packet_length_std`,
`fwd_seg_size_min` and `subflow_fwd_packets`. Six cases cannot support a claim of
method agreement or global ranking stability.

Other explainer functionality checks reported by the project used SHAP TreeExplainer on
an XGBoost model, SHAP GradientExplainer on a PyTorch model, and LIME on a synthetic
prediction function and a trained synthetic XGBoost model. These establish only that the
interfaces ran in the reported environment; they are not Evasight stability experiments.

Ignored local explanation artifacts:

- `artifacts/mlp_smoke_explanations/mlp_cic2017_smoke_shap.npz`
- `artifacts/mlp_smoke_explanations/mlp_cic2017_smoke_lime.json`
- `artifacts/mlp_smoke_explanations/mlp_cic2017_smoke_metadata.json`

## 4. Dataset and feature audit facts

- The current processed partitions contain 1,270,642/267,435/274,132 CIC-IDS2017,
  5,607,932/1,167,746/1,210,959 CSE-CIC-IDS2018 and 85,649/14,981/52,640
  UNSW-NB15 train/validation/test rows.
- `docs/audit/cic_ids2017_audit.json` reports 329,896 duplicates removed from 2,827,876
  rows (11.67%). The improved-release validation report has a different 2,099,976-row
  input population; the duplicate rate is not assigned to that version pending reconciliation.
- `docs/audit/unsw_nb15_audit.json` reports 94,928 duplicates removed from 257,673 rows
  (36.84%); this is a loader-level count, not the final processed split.
- `docs/audit/cic_ids2018_audit.json` and current processed partitions disagree on totals
  and apparent version. See `04_datasets.md` and `open_questions.md`.
- The legacy CIC controllability table has 77 columns (15/29/33 free/derived/fixed);
  the improved CIC table has 83 (15/30/38); UNSW has 42 (3/6/33).
- The CIC-IDS2017 audit reports `init_win_bytes_forward = -1` in 43.1% of benign and
  0% of attack flows; the status document reports a single-feature AUC of 0.937 and an
  approximately 40% CSE-CIC-IDS2018 gain association. These are potential dataset
  shortcut findings, not causal evidence.
