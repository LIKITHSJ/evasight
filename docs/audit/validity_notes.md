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

## Added rules (measured on the same 2,497,980 flows)
- iat_total_eq_mean_x_gaps: fwd_iat_total == fwd_iat_mean * (n_fwd - 1): 0.000% violations.
- len_std_popoviciu: std <= (max-min)/2 * sqrt(n/(n-1)) (Popoviciu): 0.000% violations.
- header_per_packet_20_60: fwd_header_length / n_fwd in [20, 60] (TCP header 20 B + options):
  0.071% violations (0.085% benign, 0.001% attack). Cause not yet inspected.
- min_seg_size_valid: min_seg_size_forward in [20, 60] and divisible by 4: 0.072% violations
  (0.087% benign, 0.001% attack). Behaves as a categorical feature (values 20/32/40/24/44).
  Perturbations must switch between observed values, never nudge it continuously.
