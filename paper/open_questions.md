# Evasight open research and provenance questions

## Data identity and preprocessing

1. Reconcile `docs/audit/cic_ids2017_audit.json` (2,827,876 input rows and 329,896
   duplicates) with the improved-release validation report (2,099,976 input rows) and
   current processed partitions. Which exact artifact does the 11.7% duplicate rate describe?
2. Reconcile the current CSE-CIC-IDS2018 processed total (7,986,637), audit JSON
   `rows_written` (2,486,278), older manuscript total (9,780,124), benign fraction 0.1,
   and duplicate counts (1,400,893 versus 1,598,383). Tie them to source and output
   checksums before publishing sampling or prevalence claims.
3. Confirm that all training artifacts were generated from the current checksum-identified
   processed files and the documented split implementation.
4. Decide and document the rare-class policy. In the current CIC-IDS2017 test partition,
   Heartbleed and SQL Injection each have two records; category recall is not a stable
   population estimate at that support. For CIC-IDS2018, investigate zero Dropbox Download
   recall (13 test records), DoS Slowloris recall (1,274 records), and Web Attack - SQL
   recall (4/6); do not generalize estimates from the smallest supports. Per-category
   recall-derived estimates are 852 raw versus 685 calibrated attack misses, with benign
   false positives increasing from about 42 to 91 at threshold 0.5. Obtain prediction
   arrays or confusion matrices to verify these derived counts before operational claims.
5. Keep the legacy 77-feature CIC controllability table separate from the improved
   83-feature table. Confirm whether the CSE-CIC-IDS2018 classifications are validated
   feature by feature or inherited solely because the columns match.

## Model and experiment provenance

6. Resolve the different historical XGBoost calibration results in the user-supplied
   experiment report versus `README.md`/`docs/STATUS.md`. Link each to model hash, split
   checksum, calibration object, predictions and exact metric calculation.
7. Strengthen independent reproducibility for the completed CIC-IDS2017 and CIC-IDS2018
   full MLP baselines: identify each source commit, associate exact dataset hashes with each
   run, archive each complete execution log, and retain test predictions/confusion matrices
   so category-level miss counts can be audited. Both runs are supported by supplied
   execution records and matching local checkpoint metadata. A same-seed CIC-IDS2018
   deterministic rerun produced identical epoch histories and byte-identical model and
   preprocessor artifacts; this supports repeatability in the tested setup but not
   cross-platform or independent benchmark reproducibility. Source/data checksum/log
   association and a complete software-environment fingerprint remain missing, and
   multi-seed variability has not been measured.
8. Complete the full UNSW-NB15 MLP run; preserve train-only preprocessing and the untouched
   test protocol.
9. Record the exact MAPLE import guard patch, SHAP package/environment hashes and Windows
   Smart App Control conditions. Do not claim an unmodified SHAP installation.
10. Resolve version warnings when loading the scikit-learn 1.9.1 preprocessor in a
    scikit-learn 1.4.2 environment; reproduce in the serialization environment or
    regenerate compatible artifacts.

## Scientific evaluation

11. Implement and define method-specific SHAP and LIME stability metrics. Separate
    explanation change from prediction-score change and explainer randomness.
12. Evaluate paired clean/perturbed flows, score-matched benign/attack controls, ordinary
    prediction instability, and clean versions of the same flows. Test whether explanation
    measurements add information beyond score and score change.
13. Pre-register split, operating threshold, calibration, metric definitions, confidence
    intervals, multiple-comparison handling and statistical tests.
14. Run full-model SHAP/LIME on both completed CIC-IDS2017 and CIC-IDS2018 MLP checkpoints.
    The six-observation CIC-IDS2017 smoke test used a separate smoke checkpoint and is not
    a full-model explanation result. Then run realistic perturbation checks across all
    datasets and adversarial explanation-stability experiments, including an adaptive
    attacker that knows the explanation-based detector.
15. Perform feature ablation and cross-capture/cross-dataset validation to test shortcut
    dependence, especially for `fwd_init_win_bytes` in CIC-IDS2018. Investigate feature
    leakage and partition independence; do not infer causality from SHAP rankings or
    single-feature AUC.
16. Complete the planned model, dataset, explainer, calibration, perturbation-budget and
    validity-rule ablations. Document unsuccessful or null results.
17. Verify the literature candidates previously named in `paper/02_related_work.md`
    (Apruzzese, Engelen, Lanvin, Arp, Slack, Warnecke, Fidel, Zaro) against primary sources.
    In particular, do not repeat the Zaro 2026 claim about 74–93% invalid perturbations
    until a complete bibliographic record and the underlying study are found.

## Publication readiness

18. Agree authorship order and contributions in `docs/authorship.md`.
19. Complete the related-work search and verify citation completeness; no "first" or
    precedence claim is currently supported.
20. Review the complete manuscript with both authors after the data, model and attack
    records are reconciled. The current work is an evolving draft, not a submission-ready
    paper.
