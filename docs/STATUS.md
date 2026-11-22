# Project status and handoff
Last updated: 2026-11-22 by Likhith. Update this file at the end of every work session.

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

## Dev findings so far (dev XGBoost, not paper results)
- Web attacks evade despite high model confidence (H1 refuted on dev model).
- Almost all evasions that need pad and delay combined are DDoS; evasion runs mainly via fwd_iat_min and average_packet_size.
- SHAP instability did not separate evaded from non-evaded flows (AUC about 0.52). Inconclusive, because the dev model was overconfident.

## Next
- Likhith: define eps relative to each feature's own value and test a tighter cap; re-run the attack on the calibrated baseline.
- Sharath: review split.py and gbdt.py; MLP baseline; LIME next to SHAP; incremental test (does instability add information beyond the raw model score).
- Both: agree authorship order in docs/authorship.md.
- Not started: evaluation statistics, paper.

## Proposed data contract (Sharath to review via PR)
data/processed/<dataset>/{train,val,test}.parquet with float32 feature columns plus
`label` (0 benign, 1 attack) and `attack_cat` (string). Splits are made by the split code;
the loader only produces cleaned full tables at data/interim/<dataset>.parquet.

## Decision log
- 2026-11-08: white-box evasion is the primary threat model; poisoning is out of scope.
- 2026-11-08: project named Evasight; repo renamed to LIKITHSJ/evasight.
- 2026-11-10 and 2026-11-17: Likhith merged PRs #9, #10 and #12 without review to keep the attack work moving. Post-merge review by Sharath is still welcome.
- 2026-11-17: CIC-IDS2017 Improved release adopted (the original release has all-zero bulk features).
- 2026-11-22: package renamed ridsx to evasight (PR #13).
- Open: authorship order (to be agreed in writing in docs/authorship.md).

## Branching convention (agreed 2026-11-08)
- Short-lived branches off main, named <owner>/<type>-<task>, e.g. likhith/feat-loaders, sharath/feat-split.
- One small PR per task; the other author reviews; merge within a few days; delete the branch after merge.
- No long-lived personal dev branches (they drift and create large, unreviewable merges).
