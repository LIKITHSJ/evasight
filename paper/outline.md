# Evasight: paper outline

Working title: *Do Explanations of a Network Intrusion Detector Remain Stable Under
Realistic Evasion?*

`paper/manuscript.md` is the current integrated working draft. The files `02_related_work.md`
through `05_attack.md` remain the editable section drafts; the experiment and reproducibility
ledgers are maintained alongside them. The manuscript is not submission-ready.

## Manuscript sections

1. Abstract — pending final results.
2. Keywords.
3. Introduction — motivate explanations as a possible complementary, not assumed, evasion signal.
4. Motivation and problem statement.
5. Research objectives and falsifiable hypotheses.
6. Related work — keep only bibliographically verified citations in the draft.
7. Threat model and problem formulation — see `03_threat_model.md`.
8. Dataset description and preprocessing — see `04_datasets.md`; reconcile stale audit totals.
9. Feature controllability and validity constraints — distinguish legacy 77-column and improved
   83-column CIC-IDS2017 schemas.
10. Detection models — XGBoost and MLP, with results separated by provenance and run type.
11. Explainability methods — SHAP and LIME; distinguish their outputs.
12. Adversarial perturbation methodology — see `05_attack.md`.
13. Explanation stability metrics — planned; no stability conclusion is established.
14. Experimental setup and reproducibility.
15. Experimental results — see `experimental_results.md`.
16. Ablation studies — pending.
17. Discussion.
18. Limitations and threats to validity.
19. Conclusion and future work — pending full evaluation.
20. References.

The original outline's white-box threat-model note is superseded: the implemented search uses
attack-score access and does not read model parameters or gradients. Remaining authorship,
citation and evidence questions are listed in `open_questions.md`.
