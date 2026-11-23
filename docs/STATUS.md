# Project status and handoff
Last updated: 2026-11-23 by Likhith. Update this file at the end of every work session.

## Project
Adversarially robust and explainable network intrusion detection (NIDS), co-authored by
Likhith (Master's in Cybersecurity) and Sharath (Master's in Data Science). Target: arXiv
preprint + workshop/conference submission. Project name: Evasight. Repo: LIKITHSJ/evasight (private).
RQ: do SHAP/LIME explanations of an IDS stay stable under constraint-respecting adversarial
perturbations, and can instability detect evasion attacks?
Datasets: CIC-IDS2017 (Improved release), CSE-CIC-IDS2018, UNSW-NB15 (never committed; see docs/checksums.txt).
Constraints: everything free; MacBook Air M2, 8 GB RAM (chunked reads, float32, Parquet).

## Action needed after pulling (2026-11-22)
The package was renamed from `ridsx` to `evasight` (PR #13). In your venv run:
`git pull && python -m pip install -e ".[dev]"` then `python -m pytest -q` (14 tests should pass).
Imports are now `from evasight...`. egg-info is no longer tracked; delete any local `src/ridsx.egg-info`.

## Rules for any AI assistant used by either author
- The AI is a tutor and reviewer. The authors decide, write and are responsible for the work.
- Explain concepts, review code, suggest options. Do not write whole modules unprompted.
- Never edit files outside the asking author's owned folders (see Ownership) without a PR.
- Read this file first. After any milestone, propose a STATUS.md update for the author to commit.
- Authors must be able to explain every line they commit. AI help is disclosed in the paper
  as the target venue requires.

## Ownership
| Area | Owner | Folders |
|---|---|---|
| Threat model, feature controllability, data audit and cleaning, attacks, validity checker | Likhith | docs/threat_model.md, src/evasight/data, src/evasight/attacks |
| Splits, models, SHAP/LIME, stability metrics, evasion detector, statistics | Sharath | src/evasight/models, src/evasight/explain, src/evasight/eval |
| Configs, paper, cross-review | Both | configs/, paper/ |

Note for Sharath: to avoid blocking the attack work, Likhith wrote a first version of
`src/evasight/data/split.py` (leak-aware split) and `src/evasight/models/gbdt.py` (calibrated
XGBoost baseline). Both are in your area. Please review them, then change or replace them as you see fit.

## Working agreement
- Branch per task (feat/...), pull request, the other author reviews by reading the code.
- Seeds in YAML configs; no hard-coded paths; no data or model files in git.
- Install: python3.12 -m venv .venv && source .venv/bin/activate && python -m pip install -e ".[dev]"
- Always use `python -m pip`, not bare `pip`.

## Done
- [x] Repo, scaffold, environment (torch with MPS, xgboost, shap, sklearn verified)
- [x] Threat model v0.1 (docs/threat_model.md) and diagram (docs/figures/)
- [x] All three datasets downloaded, SHA-256 checksums in docs/checksums.txt
- [x] Loaders to Parquet: CIC-IDS2017 Improved, UNSW-NB15, CSE-CIC-IDS2018 (streaming)
- [x] Data validator and raw-CSV trace (docs/audit/)
- [x] Feature controllability table and validity rules
- [x] Perturbation engine (pad data packets, add delay on the forward direction) with derived-feature recompute and invariant tests
- [x] Grid-search evasion attack; dev results in docs/audit/attack_dev_results.md (dev model only, not paper results)
- [x] Leak-aware split (drops Attempted, dedup, per-class time blocks, rank-capped purge) with integrity tests
- [x] Calibrated XGBoost baseline on the leak-aware split
- [x] Package renamed to evasight; egg-info untracked
- [x] Delay capped by CICFlowMeter timeouts (120 s flow, 5 s activity), measured on the Improved data (PR #15)
- [x] Model excludes split metadata (source, attempted_category) via NON_FEATURE (PR #16)
- [x] total_tcp_flow_time excluded per feature_validation.md section 10; baseline retrained as v2, 79 features (PR #18). v1 artifacts kept in artifacts/v1_with_ttft
- [x] Reproducible attack runner: python -u scripts/run_attack.py (PR #19)

## Dev findings so far (dev XGBoost, not paper results)
- Web attacks evade despite high model confidence (H1 refuted on dev model).
- Almost all evasions that need pad and delay combined are DDoS; evasion runs mainly via fwd_iat_min and average_packet_size.
- SHAP instability did not separate evaded from non-evaded flows (AUC about 0.52). Inconclusive, because the dev model was overconfident.

## Datasets ready for ML (2026-11-23)
All three: leak-aware split (conflicting-label vectors dropped, feature dedup, no vector in two partitions), calibrated XGBoost baseline, constraint-respecting attack. Files are shared as bundles, not in git; verify with shasum -a 256 -c on the checksum file.

| Dataset | Split | Baseline (calibrated) | Evasion eps 0.1 / 1.0 | Bundle / checksums |
|---|---|---|---|---|
| CIC-IDS2017 Improved | per-class time blocks 70/15/15 | 79 feats, AUC 0.9988, benign FPR 0.002% | 39 / 93 of 60,083 (0.06% / 0.15%) | cic2017 v2 bundle, docs/checksums_cic2017_v2.txt; v3 attack in the 2018+UNSW bundle |
| CSE-CIC-IDS2018 | per-class time blocks 70/15/15 | 68 feats, AUC 0.9839, benign FPR 2.01% | 802 / 1,364 of 183,487 (0.44% / 0.74%) | 2018+UNSW bundle, docs/checksums_2018_unsw_v1.txt |
| UNSW-NB15 | official train/test; val = hashed 15% of train | 42 feats, AUC 0.9661, benign FPR 25.4% | 382 / 1,002 of 18,335 (2.08% / 5.46%) | 2018+UNSW bundle |

Commands: split `python -m evasight.data.split [cic2018|unsw]`, train `python -m evasight.models.gbdt [cic2018|unsw]`, attack `python -u scripts/run_attack.py --data <test.parquet> --tag <xgb_tag> --out <dir>`.

Notes for the ML side:
- 2026-11-23: padding now updates fwd_packet_length_std, packet_length_variance and packet_length_std exactly (PR #43). v4 kept stale std values, and 16 of its 55 eps 0.1 evasions depended on them. 2017 results move to artifacts/v5 (39 / 93).
- Attack results to use: artifacts/v5 (2017), artifacts/cic2018_v2, artifacts/unsw_v2. Budgets are cumulative: an attacker with eps may use any perturbation found at a smaller eps, so evasion never falls as eps grows. In 2017, flows with forward bulk activity are not perturbed (v2 overstated slow DoS evasion).
- 2018: raw timestamps use a 12-hour clock without AM/PM, fixed in the loader (hours 1-7 are PM, checked against the published schedule). Infilteration recall is 0.26 (known label noise); report with and without it. Isotonic calibration raised ECE (0.014 to 0.024).
- UNSW: the official test set differs from train, so benign FPR at 0.5 is 25%; threshold and calibration need care. proto/service/state are integer codes (data/processed/unsw_nb15/category_codes.json). Official split sizes after the loader's dedup: train 107,740, test 55,005 (the decision register's 106,800/55,945 swaps the 940 cross-split duplicates).
- Tiny classes (2017 web attacks, 2018 SlowHTTPTest and FTP, UNSW Worms) are too small to report per class.

## Next
- Likhith: done with attacks on all three datasets (UNSW perturbation in src/evasight/attacks/unsw.py, configs/unsw_controllability.csv).
- Both: instability detector evaluation. 2017 has 93 evasions, 2018 has 1,358; add a near-evasion analysis (does instability grow with the score drop).
- Sharath: review split.py and gbdt.py; MLP baseline; LIME next to SHAP; incremental test (does instability add information beyond the raw model score).
- Both: agree authorship order in docs/authorship.md.
- Not started: evaluation statistics, paper.

## Proposed data contract (Sharath to review via PR)
data/processed/<dataset>/{train,val,test}.parquet with float32 feature columns plus
`label` (0 benign, 1 attack) and `attack_cat` (string). Splits are made by the split code;
the loader only produces cleaned full tables at data/interim/<dataset>.parquet.

## Decision log
- 2026-11-08: white-box evasion is the primary threat model; poisoning is out of scope. (Refined 2026-11-23: the attack only reads the model's score, so the attacker needs query access, not white-box access.)
- 2026-11-08: project named Evasight; repo renamed to LIKITHSJ/evasight.
- 2026-11-10 and 2026-11-17: Likhith merged PRs #9, #10 and #12 without review to keep the attack work moving. Post-merge review by Sharath is still welcome.
- 2026-11-17: CIC-IDS2017 Improved release adopted (the original release has all-zero bulk features).
- 2026-11-22: package renamed ridsx to evasight (PR #13).
- 2026-11-22: baseline v2 drops total_tcp_flow_time. Raw AUC 1.000, calibrated AUC 0.9988; calibration slightly lowers every metric, worth a look.
- 2026-11-23: all three datasets split and baselined; 2018 and UNSW bundle shared.
- 2026-11-23: attack budgets are cumulative (an attacker with eps may use any change found at a smaller eps); UNSW-NB15 attack added.
- 2026-11-23: CSE-CIC-IDS2018 switches to the improved release of Liu et al. (CNS 2022); results on the original release are superseded once the new run is done.
- 2026-11-23: Option C dropped: no experiments on the original CIC-IDS2017 release; we use the improved releases only.
- Open: dataset decision register (PR #17), changes requested. Attempted rows and dedup policy to agree.
- Open: authorship order (to be agreed in writing in docs/authorship.md).

## Branching convention (agreed 2026-11-08)
- Short-lived branches off main, named <owner>/<type>-<task>, e.g. likhith/feat-loaders, sharath/feat-split.
- One small PR per task; the other author reviews; merge within a few days; delete the branch after merge.
- No long-lived personal dev branches (they drift and create large, unreviewable merges).
