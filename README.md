# robust-xai-nids
Adversarially robust and explainable network intrusion detection.

RQ: Do SHAP/LIME explanations of an IDS stay stable under constraint-respecting
adversarial perturbations, and can instability detect evasion attacks?

Datasets (not committed): CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15.

## Setup
    python3.12 -m venv .venv && source .venv/bin/activate
    pip install -e ".[dev]"
