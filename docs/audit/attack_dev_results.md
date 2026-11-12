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
