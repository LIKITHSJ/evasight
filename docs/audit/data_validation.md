# Independent validation of cleaned datasets (src/ridsx/data/validate.py)
Result: PASS on cic_ids2017 (2,497,980 rows), unsw_nb15 (162,745), cic_ids2018 (2,486,278).
Hard checks: row/class counts match loader audits; no NaN/Inf; label == (attack_cat != BENIGN);
zero duplicate rows; all numeric features float32.

## Findings
- Constant columns (zero information; exclude from models): CIC-2017 and CIC-2018 both have
  bwd_psh_flags, bwd_urg_flags and all six bulk features (fwd/bwd avg bytes, packets, bulk rate).
  UNSW: none.
- CIC-2017 negative values (extraction-tool artifacts, about 0.1% of rows): flow_duration 107,
  flow_bytes_s 78, flow_packets_s 107, flow_iat_mean 107, flow_iat_max 107, flow_iat_min 2,880,
  fwd_iat_min 17, fwd_header_length 35, bwd_header_length 22, min_seg_size_forward 35.
  To be dropped in a later loader update; counts to be reported in the paper.
- Rare classes (< 100 rows, excluded from training/evaluation): CIC-2017 Infiltration 36,
  Web Attack Sql Injection 21, Heartbleed 11; CIC-2018 SQL Injection 84, DoS-SlowHTTPTest 55,
  FTP-BruteForce 53. UNSW: none.
- Attack rate in output: 0.1704 (2017), 0.4733 (UNSW), 0.5433 (2018, benign subsampled to 10%).

## Open point: dataset version
In our copy (original MachineLearningCSV) all six bulk features are constant zero. Sharath's
analysis of an "Improved CIC-IDS2017" (2,099,971 records) reports 86,979 nonzero forward-bulk
records, so it is a different release. To confirm with his exact file names, then decide which
version the paper uses.

## Not yet done
Layer 3: tracing individual oddities back to the raw CSV files.
