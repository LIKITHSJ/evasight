# Project status and handoff
Last updated: 2026-11-08 by Likhith. Update this file at the end of every work session.

## Project
Adversarially robust and explainable network intrusion detection (NIDS), co-authored by
Likhith (Master's in Cybersecurity) and Sharath (Master's in Data Science). Target: arXiv
preprint + workshop/conference submission. Repo: LIKITHSJ/robust-xai-nids (private).
RQ: do SHAP/LIME explanations of an IDS stay stable under constraint-respecting adversarial
perturbations, and can instability detect evasion attacks?
Datasets: CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15 (never committed; see docs/checksums.txt).
Constraints: everything free; MacBook Air M2, 8 GB RAM (chunked reads, float32, Parquet).

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

## Working agreement
- Branch per task (feat/...), pull request, the other author reviews by reading the code.
- Seeds in YAML configs; no hard-coded paths; no data or model files in git.
- Install: python3.12 -m venv .venv && source .venv/bin/activate && python -m pip install -e ".[dev]"
- Always use `python -m pip`, not bare `pip`.

## Done
- [x] Repo, scaffold, environment (torch with MPS, xgboost, shap, sklearn verified)
- [x] Threat model v0.1 (docs/threat_model.md) and diagram (docs/figures/)
- [x] UNSW-NB15 (training/testing-set CSVs) and CIC-IDS2017 (8 MachineLearningCSV files) downloaded
- [x] SHA-256 checksums in docs/checksums.txt

## Next
- Likhith: raw-data loader (CSV -> cleaned Parquet), data audit notes, feature controllability table.
- Sharath: clone, set up environment, download datasets and verify checksums; then write a
  short design note for the split protocol and baseline models before coding.
- Not started: CSE-CIC-IDS2018, attacks, models, explainability, evaluation, paper.

## Proposed data contract (Sharath to review via PR)
data/processed/<dataset>/{train,val,test}.parquet with float32 feature columns plus
`label` (0 benign, 1 attack) and `attack_cat` (string). Splits are made by Sharath's code;
the loader only produces cleaned full tables at data/interim/<dataset>.parquet.

## Decision log
- 2026-11-08: white-box evasion is the primary threat model; poisoning is out of scope.
- Open: authorship order (to be agreed in writing in docs/authorship.md).
- Open: use original CIC-IDS2017 labels or a published corrected version.

## Branching convention (agreed 2026-11-08)
- Short-lived branches off main, named <owner>/<type>-<task>, e.g. likhith/feat-loaders, sharath/feat-split.
- One small PR per task; the other author reviews; merge within a few days; delete the branch after merge.
- No long-lived personal dev branches (they drift and create large, unreviewable merges).
