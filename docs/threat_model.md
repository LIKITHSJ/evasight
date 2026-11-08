# Threat model (v0.1, DRAFT)

## 1. Setting
Flow-based NIDS: a classifier over per-flow statistics (CICFlowMeter-style features for
CIC-IDS2017/2018, UNSW-NB15 features), flagging each flow as benign or attack.

## 2. Attacker goal
Test-time evasion: modify the attacker's own traffic so a malicious flow is classified benign
while the attack still succeeds. Poisoning and model theft are out of scope.

## 3. Attacker knowledge
- Primary: white-box (model, weights, feature pipeline known). Worst-case robustness bound.
- Secondary: black-box via transfer from a surrogate model.
- Extension: adaptive attacker aware of the explanation-based detector (future work).

## 4. Feature controllability (to be finalised per dataset)
| Class | Meaning | Examples |
|---|---|---|
| Free | Attacker sets by shaping own packets | fwd packet length, fwd inter-arrival time, fwd packet count |
| Derived | Computed from free features; must stay consistent | totals, mean, std, rates (bytes/s) |
| Fixed | Attacker cannot change without breaking the attack or the protocol | protocol, destination port, backward-direction features, TCP flag semantics |

## 5. Validity constraints
1. Non-negativity and valid ranges.
2. Integer features stay integer.
3. Derived features recomputed from the free features after perturbation.
4. Fixed features unchanged.
5. Perturbations only add or pad (extra bytes, delays); malicious payload is never removed.

## 6. Perturbation budget
Bounded relative change on free features (e.g. +/-X% of the original value) and a bounded
count of changed features. X is swept in experiments, not fixed here.

## 7. Defender
Trained classifier plus an explanation module (SHAP/LIME). The defender sees only the
incoming flow and the explanation, not the attacker's intent.

## 8. Open questions
- Exact free/derived/fixed split per dataset (needs feature-by-feature review).
- Which attack families to include (DoS, brute force, web, botnet, ...).
