# 2. Related work

## Problem-space adversarial machine learning

Feature-space attacks can propose vectors that do not correspond to realizable objects.
Pierazzi et al. formalize problem-space attacks, where an attacker changes a real object and
the feature representation follows, including side effects of the change [1]. Evasight applies
that framing to flow records: packet padding and timing changes are the actions, while flow
statistics are derived consequences. The cited work concerns Android malware; it motivates
the formulation but is not evidence that Evasight's network transformations are realistic.

## Dataset quality

The authors of the improved CIC releases document their review of CIC-IDS2017 and
CSE-CIC-IDS2018 and provide corrected data and supporting documentation [4]. The specific
cleaning, split and integrity counts used here are project-local results and are recorded in
`04_datasets.md` and `experimental_results.md`; they should not be attributed to the publication
unless the specific claim is supported there.

## Explanations

SHAP presents a unified framework for additive feature-attribution explanations [2]. LIME
approximates an individual prediction locally with an interpretable surrogate [3]. These outputs
are not interchangeable: this study treats SHAP attribution vectors and LIME local-rule weights
as method-specific explanations. The project's smoke test confirms that both can produce
explanations for selected MLP examples, but it does not measure explanation stability or
validate an instability-based evasion detector.

## Scope of the literature claim

The current literature review is incomplete. Earlier drafts contained author-year references to
Apruzzese, Engelen, Lanvin, Arp, Slack, Warnecke, Fidel and Zaro without a complete, verified
bibliography. Those citations and their associated claims are not carried forward as established
evidence. They must be identified and checked before submission. No novelty or "first study"
claim is made in this draft.

The verified references used above are listed in `manuscript.md`.
