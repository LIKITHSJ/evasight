# Evasight reproducibility record

## 1. Repository and data

- Repository: `LIKITHSJ/evasight`.
- Revision inspected: `1b31bd1a63b7189a801a29a2a6e80021c119be22`.
- Branch: `sharath-mlp-baseline`.
- The worktree contains staged and unstaged changes to MLP source/tests. Model artifacts
  do not embed a commit hash; the observed `HEAD` must not be used as the model's source
  revision without a run record.
- Processed row counts are recorded in `04_datasets.md`.
- Dataset checksum manifests exist under `docs/checksums*.txt`; the CIC-IDS2017 archive
  checksum report says it has not been independently compared to a publisher checksum.
- Do not publish or commit ignored model, preprocessor, smoke-data or explanation artifacts.

## 2. Reported experiment environment

The supplied CIC-IDS2018 run record identifies the training environment as the separate
`evasight-sac-test` environment on Windows, with Smart App Control enabled, and reports
Python 3.11.6. Earlier run notes list NumPy 2.4.6, pandas 2.2.3, PyArrow 20.0.0, CPU
PyTorch 2.15.0, SciPy 1.17.1, scikit-learn 1.9.1, XGBoost 3.2.0, SHAP 0.51.0 and LIME
0.2.0.1. These were previously reported for the experiment environment, but the complete
`evasight-sac-test` environment itself is not available for direct inspection here.

The repository `.venv` was inspected locally. It runs Python 3.11.6 and contains PyTorch
2.15.0+cpu, NumPy 2.4.6, pandas 3.1.1, PyArrow 26.0.1, SciPy 1.17.1, scikit-learn 1.9.1,
XGBoost 3.2.0, SHAP 0.51.0 and LIME 0.2.0.1. This verifies the currently installed
repository-environment package versions, not that this `.venv` was the exact environment
used for the run; in particular, its pandas and PyArrow versions differ from the run notes.
An environment lock or archived `pip freeze` is still needed to bind package versions to
the experiment.

The system-path interpreter inspected separately is Python 3.11.6, PyTorch 2.2.2+cpu,
NumPy 1.26.4, pandas 2.0.3, PyArrow 23.0.1, scikit-learn 1.4.2 and XGBoost 3.2.0; SHAP
and LIME are not installed there. Loading the local MLP preprocessors with this interpreter
emitted `InconsistentVersionWarning` for StandardScaler and IsotonicRegression serialized
by scikit-learn 1.9.1. Do not use this interpreter to claim reproduction of the serialized
calibration/scaler behavior.

The original project `.venv` is to remain untouched. Reproduction should use the explicitly
documented compatible environment and record a lock file or full `pip freeze` output.

## 3. SHAP compatibility workaround

The explanation run notes report SHAP 0.51.0 and a local compatibility modification in a
Windows temporary environment: an optional scikit-learn MAPLE import was guarded because
Smart App Control blocked it. The workaround is not an Evasight methodology contribution,
is not committed here, and is not included in the repository. Its exact file, patch and
environment hash were not supplied. The explanation run therefore used a modified local
installation, not an unmodified SHAP installation. Preserve the patch and environment
details before claiming exact reproduction.

## 4. MLP run configuration present in artifacts

### Smoke checkpoint

- CIC-IDS2017 sample partitions: 20,000 train / 5,000 validation / 5,000 test, stratified.
- Seed 42; CPU, four threads; batch size 2,048; max epochs 2; patience 2; learning rate
  0.001; dropout 0.2; shuffle buffer 8,192.
- Checkpoint/preprocessor: `artifacts/mlp_smoke_models/`.
- The sampled Parquet partitions and exact invocation are not present in the inspected
  directory, so the smoke run is not independently reconstructible from the checkpoint
  alone.

### Completed full CIC-IDS2017 MLP baseline

The full CIC-IDS2017 MLP run completed successfully on 2026-11-28. The complete terminal
output was supplied directly to the research assistant, and the reported run metadata and
metrics match the local checkpoint and preprocessor. The full partition sizes were verified:
1,270,642 train / 267,435 validation / 274,132 test rows.

- Architecture: 79 → 128 → 64 → 32 → 1; learning rate 0.001; batch size 4,096.
- Maximum 50 epochs; patience 5; seed 42; CPU with four threads; shuffle buffer 65,536;
  dropout 0.2.
- Best epoch 13; best validation BCE 0.08116819488130779; training stopped at epoch 18.
- Raw and isotonic-calibrated test metrics: see `experimental_results.md`.
- Checkpoint/preprocessor: `artifacts/mlp_full_models/`.

This is a completed full-data detection baseline, not a robustness experiment. Its run is
supported by the user-supplied execution evidence and matching local checkpoint metadata;
independent reproduction is not complete. The checkpoint does not identify the source
commit or associate dataset hashes with the run. The complete terminal log has not been
archived alongside the artifacts. Source commit identification, dataset hash association and
archival of the full execution log remain required for stronger independent reproducibility.

### Completed full CSE-CIC-IDS2018 Improved MLP baseline

The full CIC-IDS2018 experiment completed on 2026-11-28. The supplied run record contains
the complete 39-epoch training/validation BCE history and the test metrics; local checkpoint
metadata matches the reported selected epoch, validation loss, configuration, selected
features and raw/calibrated test metrics. The training record states that all training rows
were used and the test partition was held back for final evaluation. Locally inspected
Parquet metadata and test labels show:

- Partitions: 5,607,932 train / 1,167,746 validation / 1,210,959 test rows.
- Test categories: 686,315 benign rows and 524,644 attack rows; per-category supports and
  raw/calibrated recall are listed in `experimental_results.md`.
- Configuration: 79 numerical inputs; hidden layers 128/64/32; one logit; Adam;
  BCEWithLogitsLoss; learning rate 0.001; batch size 4,096; max 50 epochs; patience 5;
  seed 42; CPU, four threads; shuffle buffer 65,536; dropout 0.2.
- Selection and stopping: best epoch 34; best validation BCE
  0.0017749854158630768; training stopped at epoch 39.
- Calibration: IsotonicRegression fit to validation probabilities after epoch selection.
- Test evaluation: performed after selection/calibration; no test use for stopping or
  calibration is reported.
- Checkpoint and preprocessor: `artifacts/mlp_cic2018_models/`.

The locally observed files are `mlp_cic2018_improved.pt` (89,859 bytes) and
`mlp_cic2018_improved_preprocessor.joblib` (6,034 bytes). The checkpoint does not identify
the source commit or bind the run to dataset checksums. The supplied terminal history is
transcribed into the evidence ledger, but a separately archived original execution log and
run manifest are not present. Thus this is a completed full-data baseline, not an
independently reproduced result or a robustness result.

### CIC-IDS2018 MLP — Exact Reproducibility / Deterministic Rerun

The 2026-11-28 rerun is a repeatability experiment against the original full CIC-IDS2018
baseline. The supplied run record says it reused the same dataset partitions, code path,
seed and training configuration; it is not a new independent benchmark, a new architecture,
or a third independent trial. Partition counts were verified as 5,607,932 train, 1,167,746
validation and 1,210,959 test (7,986,637 total). Both executions used 79 numerical features,
zero categorical features, hidden layers 128/64/32, ReLU, dropout 0.2 and one output logit;
learning rate 0.001, batch size 4,096, max 50 epochs, patience 5, seed 42, four CPU threads
and shuffle buffer 65,536.

The two runs produced identical epoch-by-epoch training and validation BCE histories, both
selected epoch 34 with best validation BCE 0.0017749854158630768, and both stopped after
epoch 39. Their raw and isotonic-calibrated evaluation metrics are identical to the original
benchmark (full-precision values are in `experimental_results.md`).

SHA-256 was recomputed on the original and rerun files. The original and rerun model
checkpoints are byte-identical:
`B83FE5B80B2F20258C21A627A7B67B05D3FCB096618F09B2B89F2EF440425D4C`. The original and
rerun preprocessors are also byte-identical:
`889432D5C95D19F9D36FEBC7CD9C08515D65A69AD43DF8BDE6072D933F182913`. The original
directory is `artifacts/mlp_cic2018_models/`; the rerun directory is
`artifacts/mlp_cic2018_rerun_20261128_models/`.

This is evidence of deterministic repeatability and byte-level identity under the tested
setup, not cross-platform reproducibility. The partition row counts were checked, but source
dataset files were not independently verified with cryptographic checksums. A Git commit
identifier and complete software-environment fingerprint have not been independently
associated with both runs. Only seed 42 was tested, so multi-seed variability remains
unmeasured. This rerun evaluates training repeatability only and does not validate the
hypothesis that explanation instability detects adversarial evasion.

The MLP protocol fits the numerical scaler and category vocabularies from training data
only. The validation partition is used both for early stopping and, after epoch selection,
for isotonic calibration. The test partition is evaluated after selection/calibration and is
not used for either. This validation reuse matches the established project protocol but
should be disclosed as a limitation.

## 5. Explanation smoke-test configuration

- Reported additional compatibility checks: SHAP TreeExplainer on XGBoost; SHAP
  GradientExplainer on PyTorch; LIME on a synthetic predictor, a trained synthetic
  XGBoost model and the Evasight MLP smoke checkpoint.
- Model: CIC-IDS2017 MLP smoke checkpoint, not either completed full-dataset MLP checkpoint.
- Six observations; 79 numerical features; three benign and three attack examples.
- SHAP GradientExplainer; background of 100 random training examples; 128 samples.
- LIME Tabular; 1,000 samples per observation.
- Seed: 42.
- Outputs and metadata are under `artifacts/mlp_smoke_explanations/`, ignored by Git.
- No repeated-seed or perturbation stability evaluation was performed.

## 6. Commands and missing run manifests

The project CLI supports full MLP runs such as:

```powershell
python -m evasight.models.mlp cic2017
python -m evasight.models.mlp cic2018
python -m evasight.models.mlp unsw
```

These are instructions for a future/repeated run, not a claim that the observed artifacts
were produced by these exact commands. Save the command, environment lock, `git rev-parse
HEAD`, dirty-tree diff hash, dataset checksum, stdout log, artifact checksums and test
partition identity alongside every future run.
