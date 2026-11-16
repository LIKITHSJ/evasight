# Evasight

**Explanation-stability detection of evasion attacks in network intrusion detection.**

Evasight studies whether SHAP and LIME explanations of a network intrusion detector stay
stable when an attacker perturbs a flow under realistic constraints, and whether
instability itself can reveal the evasion.

**Research question:** do SHAP/LIME explanations of an IDS stay stable under
constraint-respecting adversarial perturbations, and can instability detect evasion attacks?

## Authors
Likhith (threat model, data, attacks) and Sharath (models, explainability, evaluation).
Author order is being agreed in `docs/authorship.md`.

## Datasets (not committed)
CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15. Integrity hashes are in `docs/checksums.txt`.

## Repository layout
- `docs/` threat model, figures, audit notes, project status (`docs/STATUS.md`)
- `src/ridsx/` code (the Python package keeps its working name `ridsx` for now)
- `configs/` feature controllability table and experiment configs

## Setup
    python3.12 -m venv .venv && source .venv/bin/activate
    python -m pip install -e ".[dev]"

## Status
Preprint in preparation. Work in progress; see `docs/STATUS.md`.
