# Validity-rule calibration (CIC-IDS2017, cleaned data, 2,497,980 flows)
Rules in src/evasight/attacks/validity.py were run on real flows; violation rates (%):
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

## Derived-feature recompute (src/evasight/attacks/perturb.py: recompute_derived)
Each formula was tested against real flows before use.
- exact (round trip 100%): average_packet_size = packet_length_mean * (n+1)/n (100%);
  min_packet_length = min over directions that have packets (100%; the naive min fails on the
  169,028 flows with no backward packets); flow_bytes_s, flow_packets_s, fwd_packets_s,
  avg_fwd_segment_size, subflow_fwd_bytes, max_packet_length, flow_duration (assumption: grows
  with the forward span).
- packet_length_mean/average_packet_size carry an unexplained per-flow residual
  (average_packet_size * n - total payload; mostly small constants such as 6, 2, 31, 46;
  uncorrelated with counts or bytes). Treated as a per-flow constant (assumption).
- stale (no exact formula): packet_length_variance and packet_length_std (pooled-variance formulas
  match only 20-27% of flows; std == sqrt(variance) in 100%), flow_iat_* (flow_iat_max equals
  fwd_iat_max in only 25%), active_*, idle_*. These stay at original values after perturbation.
- Open experiment: train with and without the stale features to see whether the inconsistency is
  detectable.
