# Validity-rule calibration (CIC-IDS2017, cleaned data, 2,497,980 flows)
Rules in src/ridsx/attacks/validity.py were run on real flows; violation rates (%):
all rules 0.000 except nonneg_counts 0.001 (35 flows with negative fwd_header_length,
a counter-overflow glitch; to be dropped in the loader).

## Finding: init_win_bytes_forward is a capture shortcut
- Value -1 means no TCP handshake observed (sentinel, not a window size).
- It occurs in 43.1% of benign flows and 0.00% of attack flows.
- Validity rule is sentinel-aware: valid = -1 or a normal window size; perturbations must
  never switch a flow between -1 and a real value.
- To report as a limitation; plan an ablation without this feature.
