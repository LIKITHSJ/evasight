# 4. Datasets and data quality

## 4.1 Sources and scope

The study uses improved CIC-IDS2017 and CSE-CIC-IDS2018 files supplied with the
Error Prevalence project [4], and the official UNSW-NB15 training/testing release
described on the UNSW dataset page [5]. We do not redistribute source data. The local
SHA-256 manifests in `docs/checksums*.txt` identify the bundles used in the project; the
CIC-IDS2017 archive checksum recorded in `docs/audit/cic_ids2017_feature_validation.md`
has not been compared against an independently published checksum.

The following row counts were read directly from the current processed Parquet partitions:

| Dataset | Train | Validation | Test | Feature count in baseline |
|---|---:|---:|---:|---:|
| CIC-IDS2017 Improved | 1,270,642 | 267,435 | 274,132 | 79 |
| CSE-CIC-IDS2018 Improved | 5,607,932 | 1,167,746 | 1,210,959 | 79 |
| UNSW-NB15 | 85,649 | 14,981 | 52,640 | 42 |

These are current split sizes, not claims about the source population. CIC partitions are
split into train/validation/test time blocks by class (70/15/15 target fractions with
rank-capped purging). The UNSW test partition follows the official split; validation is
selected from official training data by a stable hash. Conflicting-label feature vectors and
duplicate vectors are removed, and the split implementation is designed to prevent the same
feature vector from appearing across partitions. Details and tests are in
`src/evasight/data/split.py` and `tests/test_split.py`.

## 4.2 Data-cleaning audits and unresolved version mismatches

The project audit `docs/audit/cic_ids2017_audit.json` reports 329,896 duplicates removed
from 2,827,876 rows (11.67%). The improved-release validation report instead identifies
2,099,976 source rows, five non-finite rows removed, and 2,099,971 cleaned rows. The
reported 11.7% duplicate rate therefore must not be attributed to the improved-release
source without reconciling these distinct audit scopes. The final CIC-IDS2017 processed
partitions contain 1,812,209 rows after split-specific exclusions and purging.

For UNSW-NB15, `docs/audit/unsw_nb15_audit.json` records 94,928 duplicate rows removed
from 257,673 input rows (36.84%). The split pipeline then applies additional conflict,
deduplication and partition rules; its current processed counts are those in the table above.
The loader-level duplicate fraction and final split sizes describe different stages.

CSE-CIC-IDS2018 records are not yet reconciled across project sources. The current processed
partitions sum to 7,986,637 rows. `docs/audit/cic_ids2018_audit.json` reports
`benign_frac_kept: 0.1` but also reports 2,486,278 rows written; the older prose in this
section's history describes 9,780,124 rows, while `docs/STATUS.md` reports 1,400,893
duplicates and the audit JSON reports 1,598,383. Until the source bundle, loader audit,
processed partitions and checksum manifest are tied to one immutable version, the 10%
benign-sampling claim and these totals are provisional and must not be combined.

## 4.3 Labels, exclusions and feature sets

The binary target is `label` (benign 0, attack 1); `attack_cat` is retained only for
stratified reporting. Split metadata such as `source` and any `attempted_category` field
must not enter model inputs. The XGBoost baseline's `EXCLUDE` set is reused by the MLP.
The MLP additionally uses only the training partition to remove constant features and fit
preprocessing. The selected full CIC-IDS2017 checkpoint contains 79 numerical features.
The project baselines use 79 features for each improved CIC release and 42 for UNSW-NB15.
For UNSW, `proto`, `service` and `state` are categorical in the MLP; vocabularies are learned
from train only, index zero is reserved for unknown/missing categories, and numerical
features are standardized using train only.

The improved CIC-IDS2017 validation report documents negative extraction values in selected
fields, including forward/backward header lengths, and motivates excluding header lengths.
`total_tcp_flow_time` is also excluded because its provenance could not be established.
These decisions are described in `docs/audit/cic_ids2017_feature_validation.md`.

## 4.4 Dataset artefacts and shortcuts

The feature validation report finds that `init_win_bytes_forward = -1` occurs in 43.1% of
benign flows and 0% of attack flows in its CIC-IDS2017 audit population. `docs/STATUS.md`
also reports a single-feature AUC of 0.937 and approximately 40% of CSE-CIC-IDS2018 model
gain associated with `fwd_init_win_bytes`; these are project-reported audit/model findings,
not causal evidence. The feature may encode capture or host-stack provenance. The implemented
padding-and-delay attack does not change it, so it remains a potential shortcut under that
action space. Performance must be interpreted with an ablation and cross-capture validation,
not as evidence of general intrusion-detection ability.

The improved CIC-IDS2017 report also identifies one source-level URG-feature inconsistency,
non-zero bulk-statistics features, and a mismatch between some rules and non-TCP flows.
Validity rules are therefore conditional on protocol where required. For CSE-CIC-IDS2018,
the original release's 12-hour timestamps without AM/PM are not treated as a problem in the
improved release; the project reports UTC timestamps for the improved data. The full audit
trail is in `docs/audit/`.

## 4.5 Feature controllability counts

The counts depend on the feature schema and must not be conflated. The legacy
`configs/cic2017_controllability.csv` has 77 rows: 15 free, 29 derived and 33 fixed. The
improved CIC-IDS2017 table has 83 rows: 15 free, 30 derived and 38 fixed. The improved
CSE-CIC-IDS2018 release shares that schema. The UNSW-NB15 table has 42 rows: 3 free,
6 derived and 33 fixed. These counts were checked against the CSV files; they are
engineering classifications for the implemented perturbations, not a proof of universal
attacker capability.

## 4.6 Open data-integrity work

Before final analysis, reconcile the CIC-IDS2017 audit denominator and CIC-IDS2018 version,
sampling fraction, duplicate totals and processed partition checksum. Confirm that the
processed Parquet files match the bundle manifest used in training. Record any rare-class
removal or retention policy per split; class-specific metrics with only a few test examples
are descriptive and not stable estimates.
