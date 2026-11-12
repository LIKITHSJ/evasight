# Attack development results (NOT paper results)
Setup: throwaway XGBoost (200 trees, depth 8) on a 600,000-row random sample of cleaned CIC-IDS2017,
random 80/20 split, 69 non-constant features. 20,396 attack flows caught by the model were attacked
with grid_attack (5 x 5 pad/delay levels, validity-checked, derived features recomputed).
Random-split scores are inflated (AUC 1.0000); Sharath's leakage-free models will replace this model.

## Evasion rate vs budget eps (both knobs)
eps 0.1: 0.55% | eps 0.25: 0.87% | eps 0.5: 3.94% | eps 1.0: 4.65%. 0.000% adversarial flows break a rule.

## Which knob evades (eps 1.0)
pad only 0.78% | delay only 0.70% | both 4.65%; 648 flows evade only when both knobs are combined.
By class (n >= 50): Web Attack Brute Force 0.85 (60 flows, delay alone suffices), Bot 0.143 (70, delay),
DoS Slowhttptest 0.091 (254, delay), DDoS pad 0.026 / delay 0.000 / both 0.132 (6,132), slowloris 0.011,
GoldenEye 0.002, Hulk 0.003, PortScan 0.001, FTP-Patator and SSH-Patator 0.000.
Small classes (Bot, Web Brute Force; XSS 29 flows; Infiltration 2) have wide error bars.

## Observations
- The model's top features are backward-direction (bwd_packet_length_std 45% of importance), which
  the threat model puts out of the attacker's reach; this probably limits evasion.
- Dropping init_win_bytes_forward lowers attack F1 only from 0.9975 to 0.9957 (Bot recall 0.76 -> 0.52).
- Hypotheses not yet tested: why web attacks evade (closeness to the decision boundary?); whether the
  648 combination-only flows are mostly DDoS.

## Hypothesis tests (dev model, eps 1.0)
- H1 (web attacks evade because they sit near the decision boundary): REFUTED. Web Brute Force flows
  score 0.988-0.999 before the attack, none below 0.9; DDoS scores 1.000. Only Bot (37% of flows
  below 0.9, 70 flows) fits.
- H2 (combination-only evasion is mostly DDoS): CONFIRMED. 647 of the 648 flows that evade only with
  both knobs are DDoS, 1 is PortScan.
- Evasion runs through timing and size: fwd_iat_min rises by a median factor of ~68,700 (DDoS evaded)
  and ~1,460 (Web Brute Force evaded); average_packet_size by 1.5x for DDoS. Caution: the budget eps
  is relative to the mean gap, not to the feature's own value; the paper must define this and should
  test a tighter per-feature cap.
- TreeSHAP shifts also appear on features the attacker never changed (bwd_packet_length_std,
  destination_port, bwd_header_length), because tree attributions depend on feature context.

## Can explanation instability detect evasion? (dev model, 10 random probes at eps 0.1)
Positives: 949 evaded adversarial flows. Negatives: ordinary benign flows. AUC:
- all benign flows: SHAP instability 0.524, score instability 0.753, raw score 0.999
- benign flows within the evaded score range (533 flows): 0.596 / 0.704 / 0.901
- score-binned: band 0-0.01 (79 vs 3000): 0.516 / 0.691 / 0.995; band 0.05-0.15 (117 vs 38):
  0.309 / 0.225 / 0.513. Bands 0.01-0.05 (4 vs 108), 0.15-0.3 (260 vs 18), 0.3-0.5 (489 vs 8) have
  too few flows in one group to test.
Conclusion: no evidence that SHAP instability detects evasion here, but the test is inconclusive.
The dev model is overconfident, so honest benign flows rarely score between 0.15 and 0.5, where most
evaded flows land; a confidence check alone already flags them. A fair test needs models whose
scores are spread across the range, on a leakage-free split, and an incremental analysis (does
explanation instability improve a detector that already uses the score?), with LIME and an MLP as well.
