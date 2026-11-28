# Do Explanations of a Network Intrusion Detector Remain Stable Under Realistic Evasion?

**Working manuscript — evidence status: preliminary; not submission-ready**

Project: Evasight
Repository revision inspected: `1b31bd1` (`HEAD`; working tree also contains staged and
unstaged model/test changes). Experiment artifacts do not record a source revision.

## 1. Abstract

Network intrusion detectors operate on flow summaries that constrain which feature
perturbations an attacker can realize. This work asks whether changes in SHAP and LIME
explanations under packet-level, validity-constrained perturbations provide information about
evasion beyond changes in the detector's score. The Evasight project uses improved
CIC-IDS2017 and CSE-CIC-IDS2018 data and the official UNSW-NB15 train/test release; it
implements packet padding and timing transformations, XGBoost baselines and an MLP baseline.
The current evidence includes prior XGBoost and attack reports, a stratified MLP smoke test,
completed full CIC-IDS2017 and CSE-CIC-IDS2018 MLP baselines, and explanations for six
CIC-IDS2017 smoke-test observations. Both completed MLPs are detection baselines, not
robustness experiments, and stronger independent reproducibility remains incomplete. No
completed experiment establishes that explanation instability is evasion-specific, consistent
across methods, or informative after controlling for prediction-score changes. Full-model
explanations, the UNSW-NB15 MLP baseline, controlled stability analysis and statistical
testing remain necessary.

## 2. Keywords

Network intrusion detection; adversarial evasion; explainable machine learning; SHAP; LIME;
problem-space attacks; dataset quality; calibration.

## 3. Introduction

Flow-based network intrusion detection systems (NIDS) classify traffic using summary
statistics computed by flow meters. Explanations are increasingly used to help analysts
inspect such predictions, but it is not established whether the explanations remain useful
when an attacker changes traffic while preserving the attack's function.

Evasight studies a specific question: can changes in SHAP and LIME explanations provide
additional evidence of evasion beyond what the classifier's prediction score reveals? The
study changes attacker-controlled packets and recomputes affected flow features rather than
editing an arbitrary feature vector. The goal is to test this hypothesis, not to assume that
explanation instability detects attacks.

This draft records the current project design, available evidence and provenance gaps.
Results are separated into project-reported historical baselines, smoke-test observations and
the completed CIC-IDS2017 MLP baseline. The experiment ledger in
`experimental_results.md` is the detailed record; the completed MLP baseline does not
constitute a robustness result or independent reproduction.

## 4. Motivation and Problem Statement

An explanation may change because the model's decision changes, because the input moves
through a different region of the model, because an explainer is stochastic, or because the
perturbation creates an out-of-distribution flow. Those causes are not equivalent. A useful
evasion signal must therefore be evaluated against prediction-score changes and ordinary
non-adversarial variability, not merely by showing that an attribution vector changes after
an attack.

The problem is to determine whether explanation changes associated with valid, attacker-made
traffic transformations distinguish evasion from appropriate comparison cases, and whether
they add information after the model score and score change are already known.

## 5. Research Objectives and Hypotheses

The primary research question is:

> Can instability in SHAP and LIME explanations under realistic attacker-controlled
> perturbations provide additional evidence of adversarial evasion in NIDS beyond the
> detector's prediction score alone?

The hypotheses are to be tested, not presumed:

- **H1 — association:** explanation changes are associated with successful evasion after
  accounting for the raw score and its change.
- **H2 — incremental value:** adding explanation-derived measurements improves detection of
  evasion over a score-only comparator on held-out data.
- **H3 — method and model dependence:** any signal varies across SHAP and LIME, model
  families, datasets and attack categories.
- **H4 — evasion specificity:** explanation changes distinguish adversarially perturbed flows
  from clean versions of the same flows and from suitable score-matched controls.

No hypothesis is supported by the current small-sample explanation experiment. Evaluation
protocols, controls and statistical analysis are outstanding.

## 6. Related Work

Problem-space adversarial machine learning changes a real object and lets its feature
representation follow; Pierazzi et al. formalize this setting and discuss side effects of
real-object transformations [1]. Evasight applies that framing to network flows, where
packet-level changes affect derived statistics. The cited work concerns Android malware and
does not validate Evasight's network actions.

SHAP provides a unified additive feature-attribution framework [2]. LIME explains an
individual prediction by fitting a locally interpretable surrogate [3]. Their outputs and
assumptions differ, so attribution magnitude, rankings and local rule weights must be
analysed separately.

The improved CIC data release authors document errors in CIC-IDS2017 and
CSE-CIC-IDS2018 and provide corrected data and supporting material [4]. The project also
uses the UNSW-NB15 dataset and its official train/test release [5]. Project-local quality
audits and split procedures are documented separately in `04_datasets.md`.

The literature review is incomplete. Earlier draft citations that lack verified bibliographic
records are excluded from the reference list; the open questions ledger identifies those
requiring verification. This manuscript makes no priority or novelty claim.

## 7. Threat Model and Problem Formulation

Let a flow be represented by \(x \in \mathcal{X}\), with binary label \(y\in\{0,1\}\) and
detector attack score \(s(x)\). The operating threshold used in the project is
\(\tau=0.5\). An attack transformation \(T_\theta\) is parameterized by padding and delay
choices \(\theta\), and is admissible only when its resulting traffic and recomputed
features satisfy the dataset-specific validity constraints.

For the implemented XGBoost attack, \(s\) is the isotonic-calibrated attack probability
returned by the attack runner. An evasion event is
\[
E(x,T_\theta)=\mathbb{1}\{y=1,\ s(x)\geq\tau,\ s(T_\theta(x))<\tau\}.
\]
The primary implemented attacker can query the attack score. It does not use model
parameters or gradients, and it has more information than a label-only attacker. It controls
only its own forward/source packets and does not poison training data. The assumed
availability of score queries must be justified for any deployment interpretation.

For an explanation method \(g\), let \(g(x)\) denote that method's explanation of the
prediction. The study considers the relation between \(E\), score change
\(\Delta_s=|s(T_\theta(x))-s(x)|\), and method-specific explanation change
\(\Delta_g=d_g(g(T_\theta(x)),g(x))\). The choice and normalization of \(d_g\) are
experimental decisions, not established results. See `03_threat_model.md`.

## 8. Dataset Description and Preprocessing

The datasets are improved CIC-IDS2017, improved CSE-CIC-IDS2018 and UNSW-NB15. Current
processed partitions contain 1,270,642/267,435/274,132, 5,607,932/1,167,746/1,210,959
and 85,649/14,981/52,640 train/validation/test rows, respectively. The baseline feature
sets contain 79, 79 and 42 features. `label` is the binary target; attack-category and split
metadata are excluded from model inputs.

The CIC splits are class-wise time blocks with duplicate/conflicting-label handling and
purging near split boundaries. UNSW-NB15 retains the official test partition and derives
validation from official training data. Numerical scaling and categorical vocabularies for the
MLP are learned from training only. Full data-source counts and duplicate rates have
version-specific conflicts; Section 15 and `04_datasets.md` state which counts are verified
and which remain unresolved.

## 9. Feature Controllability and Validity Constraints

The project distinguishes free, derived and fixed features. The legacy CIC configuration has
77 features (15/29/33); the improved CIC-IDS2017 configuration has 83 (15/30/38), shared
by the improved CSE-CIC-IDS2018 schema; UNSW-NB15 has 42 (3/6/33). These counts come
from the tracked configuration tables and classify the implemented transformations, not all
possible attacker capabilities.

The project reports `init_win_bytes_forward = -1` for 43.1% of benign and 0% of attack
flows in a CIC-IDS2017 audit, and reports a single-feature AUC of 0.937 and approximately
40% of CSE-CIC-IDS2018 model gain associated with the corresponding forward initial-window
feature. These observations suggest a capture/host-stack shortcut, not a causal attack
signal. The current padding/delay transformations leave the initial window unchanged. An
ablation and cross-capture validation are required before interpreting its predictive value.

Validity constraints include packet-size/MTU limits, flow-meter timeouts, preservation of
fixed fields, recomputation of derived fields and empirically calibrated invariants. A small
number of clean flows violate some rules; the reports and exclusions are dataset-specific.
See `docs/audit/validity_notes.md` and `05_attack.md`.

## 10. Machine Learning Detection Models

The established baseline is XGBoost [6], trained on the leak-aware partitions and calibrated
with isotonic regression using validation probabilities. A one-logit MLP baseline uses
standardized numerical inputs, optional training-only categorical embeddings with dimension
\(\operatorname{clip}(\operatorname{round}(\sqrt{K}),2,50)\) for training cardinality \(K\),
hidden widths 128/64/32, ReLU, dropout 0.2, Adam and unweighted binary cross-entropy with
logits. It uses CPU mini-batches and validation BCE for early stopping. For the MLP,
validation is used both for
early stopping and, after epoch selection, isotonic calibration, matching the documented
baseline protocol. This reuse is a limitation and must be disclosed.

The full CIC-IDS2017 and CSE-CIC-IDS2018 MLP baselines completed full-partition training and
test evaluation, supported by supplied execution records and matching local checkpoint
metadata. Both use 79 numerical inputs and the 128/64/32 hidden architecture, Adam,
BCEWithLogitsLoss, learning rate 0.001, batch size 4,096, maximum 50 epochs, patience 5,
seed 42, four CPU threads, shuffle buffer 65,536 and dropout 0.2. The CIC-IDS2017 model
selected epoch 13; the CIC-IDS2018 model selected epoch 34. These are detection baselines,
not robustness experiments. Source commit identification, dataset-hash association and
archival of full execution logs remain outstanding for stronger independent
reproducibility. The full UNSW-NB15 MLP baseline remains pending.

## 11. Explainability Methods

The project uses SHAP and LIME. An exploratory MLP smoke test used GradientExplainer with
a 100-row training background and 128 samples, and LIME Tabular with 1,000 samples per
observation. Six smoke-test observations (three benign and three attack) received both
explanation types using the separate MLP smoke checkpoint, not the completed full MLP
checkpoint. The SHAP array had shape \((6,79)\). These settings and outputs are descriptive
only; they do not establish global importance, robustness or stability.

SHAP attribution values and LIME local-surrogate weights are method-specific. Global
aggregation across a sample is not interpreted as causal feature importance.

## 12. Adversarial Perturbation Methodology

The attack acts in the packet/problem space through payload padding and inter-packet delay
on attacker-controlled packets. Each action is bounded relative to flow-specific quantities;
derived flow features are recomputed where supported by validation evidence. Flow-meter
timeouts and protocol-specific packet constraints are enforced. The attack searches a grid
over padding and delay and carries forward the best valid result as budgets increase.

Some feature formulas are approximate or have unexplained residuals, and some flows are
left unchanged when a valid transformation cannot be constructed. These restrictions and
assumptions are detailed in `05_attack.md`; they limit the claim to the implemented
transformations and flow-summary data.

## 13. Explanation Stability Metrics

No explanation-stability metric has yet been validated for the full Evasight evaluation.
Candidate measurements include paired attribution-vector cosine similarity, Spearman
correlation of feature rankings, top-\(k\) overlap, sign consistency, attribution-magnitude
change and repeated-run variance. LIME rule weights require a separately defined comparison
because rule sets may differ between explanations. These are planned analyses, not reported
results.

Prediction-score changes must be reported separately from explanation changes. Any
evasion classifier using explanation metrics must be compared with a score-only model and
evaluated with score-matched controls, clean/adversarial pairs and held-out data.

## 14. Experimental Setup

The established evaluation partitions are untouched by training and calibration except for
the explicitly shared validation use described above. The test set is evaluated only after
model/epoch selection. Report ROC-AUC, PR-AUC, Brier score, 15-bin fixed-width ECE, interpolated TPR at 1% FPR,
benign false-positive rate at threshold 0.5 and category-specific recall where the category
has enough test samples to support a descriptive estimate.

The completed full CIC-IDS2017 MLP run used 1,270,642 training, 267,435 validation and
274,132 test rows. Validation was used for early stopping and, after selecting the best
epoch, isotonic calibration, consistent with the existing baseline protocol. The test
partition was evaluated only after selection and calibration.

The completed full CSE-CIC-IDS2018 MLP run used 5,607,932 training, 1,167,746 validation
and 1,210,959 test rows (7,986,637 total). The complete training partition was used;
validation supported early stopping and post-selection isotonic calibration; test data was
reserved for final evaluation. The full run stopped at epoch 39 after selecting epoch 34.

An exact reproducibility rerun repeated the same partitions, code path, seed and training
configuration. It produced identical epoch-by-epoch BCE histories and identical checkpoint
and preprocessor SHA-256 hashes. This is evidence of deterministic repeatability in the
tested setup, not a third independent trial or cross-platform reproducibility; only seed 42
was tested.

The current local Windows interpreter and the separately reported compatibility environment
differ. The MLP preprocessors were serialized with scikit-learn 1.9.1; loading them with
the inspected system interpreter's scikit-learn 1.4.2 emitted version warnings. A local
SHAP MAPLE-import workaround was also reported. Full execution details and limitations are
in `reproducibility.md`.

## 15. Experimental Results

The historical project status reports calibrated XGBoost AUCs of 0.9988, 1.0000 and 0.9661
for CIC-IDS2017, CSE-CIC-IDS2018 and UNSW-NB15. A separately supplied historical report
gives calibrated AUCs of 0.99937 and 0.96395 for CIC-IDS2017 and UNSW-NB15, respectively;
the CSE-CIC-IDS2018 calibrated AUC was not supplied. Local model files confirm the best
iterations (283, 306 and 475) but do not resolve this metric discrepancy. These XGBoost
values remain version-unreconciled historical reports.

The project status reports 93 CIC-IDS2017, 197 CSE-CIC-IDS2018 and 1,002 UNSW-NB15
evasions at \(\epsilon=1.0\), among 60,083, 524,539 and 18,335 initially detected attacks,
respectively. These status-record results have not been independently rerun in this
documentation update.

The MLP smoke checkpoint reports raw/calibrated ROC-AUC of 0.9703/0.9755,
Brier score 0.0891/0.0374 and ECE 0.2340/0.0204 on its stratified 5,000-row sample test.
The completed full CIC-IDS2017 MLP baseline selected epoch 13 (best validation BCE
0.08116819488130779) and stopped at epoch 18. Its exact raw/calibrated test metrics are:

| Metric | Raw | Isotonic calibrated |
|---|---:|---:|
| ROC-AUC | 0.9995144622 | 0.9994083069 |
| PR-AUC | 0.9988095222 | 0.9982143313 |
| Brier score | 0.0028689960 | 0.0031982549 |
| ECE | 0.0024555096 | 0.0077651668 |
| TPR@1% FPR | 0.9944286922 | 0.9943791927 |
| Benign FPR@0.5 | 0.0005705654 | 0.0003834948 |

These are completed-baseline results supported by the user-supplied execution output and
matching local checkpoint metadata, not an independently reproduced result. The full
configuration, partition sizes, raw and calibrated metrics, and remaining provenance gaps
are detailed in `experimental_results.md`.

The completed full CSE-CIC-IDS2018 Improved MLP baseline selected epoch 34 (best validation
BCE 0.0017749854158630768) and stopped at epoch 39. Its raw and isotonic-calibrated test
results are:

| Metric | Raw | Isotonic calibrated |
|---|---:|---:|
| ROC-AUC | 0.9998328333 | 0.9996433201 |
| PR-AUC | 0.9998393043 | 0.9996211737 |
| Brier score | 0.0007066405 | 0.0005755883 |
| ECE | 0.0011599217 | 0.0003442207 |
| TPR@1% FPR | 0.9993081023 | 0.9993067597 |
| Benign FPR@0.5 | 0.0000611964 (0.00612%) | 0.0001325922 (0.01326%) |

Calibration improved Brier score by approximately 18.5% and ECE by 70.3%, but slightly
reduced ROC-AUC and PR-AUC, left TPR@1% FPR nearly unchanged, and increased benign FPR
at threshold 0.5. Calibration therefore did not improve every metric.

The actual CIC-IDS2018 test partition contains 686,315 benign rows and 524,644 attack
rows (about 43.32% attacks). At threshold 0.5, DoS Slowloris had 341 derived raw misses
among 1,274 examples, and Infiltration - NMAP Portscan had 427 among 7,732; together they
account for about 90% of the 852 derived raw attack misses. Isotonic calibration reduced
the estimated attack misses to 685, but estimated benign false positives increased from
about 42 to 91 among 686,315 benign examples. These counts are derived from checkpoint
recalls and observed category supports; prediction arrays and confusion matrices were not
available to verify them directly.

Infiltration - Dropbox Download had zero recall on all 13 test examples, an observed
detection failure on a very small sample rather than proof of general inability to detect
that class. Web Attack - SQL recall was 4/6 before and after calibration, also highly
uncertain. Category support and raw/calibrated recall and derived-miss details are in
`experimental_results.md`.

The fixed 0.5 threshold represents only one operating point, and calibration's trade-off
between missed attacks and benign false positives depends on operational costs. Overall
ROC-AUC measures ranking over thresholds; it does not alone establish detection effectiveness
at a selected threshold or under the test set's class prevalence. Rare-category uncertainty
and class-specific false negatives therefore remain important despite the near-perfect
aggregate AUC.

The deterministic CIC-IDS2018 rerun also matched the original run's full epoch-by-epoch
training and validation BCE histories, selected epoch 34 and stopped after epoch 39. Its
checkpoint and preprocessor are byte-identical to the original artifacts. This confirms
repeatability under the tested seed/setup, not an independent benchmark or validation of
explanation-instability detection. Hashes and the remaining cross-platform, source-revision,
dataset-checksum and environment-fingerprint limitations are recorded in
`reproducibility.md`.

The exceptionally high CIC-IDS2018 ROC-AUC and PR-AUC measure benchmark discrimination,
not adversarial robustness. `fwd_init_win_bytes` is included among the MLP's selected
features and was previously identified as a potentially strong capture/host-stack shortcut.
Feature ablation, leakage and partition-independence checks, and cross-capture validation
are needed to determine how much these results depend on dataset artifacts.

The six-observation SHAP/LIME test used the MLP smoke checkpoint, not the completed full
MLP checkpoint, and does not measure stability. No current result establishes explanation
instability as an evasion signal. The full MLP baseline's execution log has not been
archived, and source commits and dataset hash associations for the full MLP runs remain
unknown. Separately, the XGBoost metrics are version-unreconciled and the CIC-2018 data
audit has unresolved version conflicts.

The project status file also reports a development experiment in which SHAP instability
alone did not separate evaded flows from benign examples (AUC about 0.52); the analysis was
inconclusive because the development model was overconfident and the comparison groups
were not fully controlled. A later CIC-IDS2017 development analysis reports that instability
tracked attack-likeness rather than evasion specificity. Neither result establishes the
research hypothesis.

## 16. Ablation Studies

Pending: remove or control for the initial-window shortcut; compare stale/inconsistent
features with and without them; compare XGBoost and MLP; vary calibration; evaluate
score-only versus score-plus-explanation detectors; and test explainer randomness and
background/sample-size sensitivity. No ablation result is claimed here.

## 17. Discussion

Very high detection scores on CIC data require caution because labels may correlate with
capture day, host stack or other collection artefacts. A high attack score or attribution to a
feature is not proof of causal or generalizable detection. The observed `init_win_bytes`
association is especially important because the current padding/delay action does not change
it. Conversely, instability may reflect the model's decision boundary, perturbation
off-manifold effects or explainer randomness rather than evasion itself.

The CIC-IDS2018 MLP's near-perfect test discrimination is not evidence that the model is
robust to adversarial evasion. CIC-specific capture shortcuts, feature leakage, partition
independence and rare-category support require further checks. The current evidence supports
continuing the investigation, not treating explanations as an operational evasion detector.

## 18. Limitations and Threats to Validity

The study uses flow summaries rather than packet captures for full re-execution of every
flow; the attack therefore depends on documented assumptions when reconstructing derived
features. Dataset versions and audit totals are not yet fully reconciled. The current
explanation validation has only six observations. Some attack categories have very small
test support (including two Heartbleed and two SQL-injection test records in the current
CIC-IDS2017 split), so their recall estimates are highly uncertain.

The full CIC-IDS2017 MLP run completed, supported by user-supplied execution output and
matching local checkpoint metadata. Its source commit and dataset hash association have not
been identified, and the complete execution log has not been archived; independent
reproducibility therefore remains incomplete. Validation is reused for early stopping and
calibration. The six-example SHAP/LIME smoke test used a separate smoke checkpoint, not the
full MLP checkpoint.
The full CIC-IDS2018 MLP run is also completed, but its source revision, dataset-hash
association and archived full execution log are missing. Its category recalls for Dropbox
Download (0/13), Web Attack - SQL (4/6) and DoS Slowloris (below 74% on 1,274 samples)
need follow-up; several other attack categories also have small supports. The processed
CIC-IDS2018 partitions sum to the reported 7,986,637, but audit records and historical
dataset totals remain inconsistent. Neither full MLP baseline has been evaluated for
adversarial robustness, and full-model SHAP/LIME explanations have not been run.
The SHAP compatibility modification was local and is not captured as a tracked patch.
Adaptive attackers, other capture environments, and generalization to real operational
traffic remain untested.

## 19. Conclusion and Future Work

Whether explanation instability adds evidence of evasion beyond prediction scores remains
unanswered. Neither completed CIC MLP baseline is a robustness result. The next steps are
to complete source/data/log provenance, run the UNSW-NB15 MLP baseline, investigate rare
CIC-IDS2018 category misses, test the CIC-IDS2018 `fwd_init_win_bytes` shortcut through
ablation and cross-capture analysis, generate SHAP/LIME explanations for both full-dataset
checkpoints, evaluate perturbations under paired controls, and perform statistical
comparisons against score-only baselines across all three datasets. No claim that SHAP or
LIME instability detects evasion is supported at this stage.

## 20. References

[1] F. Pierazzi, F. Pendlebury, J. Cortellazzi, and L. Cavallaro, “Intriguing Properties of
Adversarial ML Attacks in the Problem Space,” *2020 IEEE Symposium on Security and
Privacy*, pp. 1332–1349, 2020. DOI:
[10.1109/SP40000.2020.00073](https://doi.org/10.1109/SP40000.2020.00073).

[2] S. M. Lundberg and S.-I. Lee, “A Unified Approach to Interpreting Model Predictions,”
*Advances in Neural Information Processing Systems 30*, 2017. [Official proceedings
page](https://proceedings.neurips.cc/paper/2017/hash/8a20a8621978632d76c43dfd28b67767-Abstract.html).

[3] M. T. Ribeiro, S. Singh, and C. Guestrin, “Why Should I Trust You? Explaining the
Predictions of Any Classifier,” *Proceedings of the 22nd ACM SIGKDD International
Conference on Knowledge Discovery and Data Mining*, pp. 1135–1144, 2016. DOI:
[10.1145/2939672.2939778](https://doi.org/10.1145/2939672.2939778).

[4] L. Liu, G. Engelen, T. Lynar, D. Essam, and W. Joosen, “Error Prevalence in NIDS
datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018,” *2022 IEEE Conference
on Communications and Network Security (CNS)*, pp. 254–262, 2022. [Official project
page and supplementary material](https://intrusion-detection.distrinet-research.be/CNS2022/).

[5] N. Moustafa and J. Slay, “UNSW-NB15 dataset,” UNSW Canberra. [Official dataset page,
including recommended publications](https://research.unsw.edu.au/projects/unsw-nb15-dataset).

[6] T. Chen and C. Guestrin, “XGBoost: A Scalable Tree Boosting System,” *Proceedings of
the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*,
pp. 785–794, 2016. DOI:
[10.1145/2939672.2939785](https://doi.org/10.1145/2939672.2939785).
