# CIC-IDS2017 Feature Analysis Notes

## 1. Purpose and scope

This document records focused investigations into URG-flag consistency and bulk-statistics feature behaviour in the improved CIC-IDS2017 dataset.

The findings supplement the detailed analysis in
`cic_ids2017_feature_validation.md`. They do not replace the full validation report.

## 2. URG-flag consistency

### Features examined

- `fwd_urg_flags`
- `urg_flag_count`

### Findings

- Exact matches: 2,099,970 records.
- Mismatches: 1 record.

The mismatch was verified in the original Thursday CSV:

| Field | Value |
|---|---|
| Source file | `thursday.csv` |
| Source row | 423478 |
| Fwd URG Flags | 0 |
| URG Flag Count | 2 |
| Label | BENIGN |

The inconsistency is present in the original source data and was preserved during preprocessing.

### Provisional decision

Retain both features provisionally. Document the source-level inconsistency and do not silently correct or relabel the affected record.

## 3. Bulk-statistics feature analysis

### Features examined

Forward-direction features:

- `fwd_bytes_bulk_avg`
- `fwd_packet_bulk_avg`
- `fwd_bulk_rate_avg`

Backward-direction features:

- `bwd_bytes_bulk_avg`
- `bwd_packet_bulk_avg`
- `bwd_bulk_rate_avg`

### 3.1 Zero-value distribution

| Feature group | Zero records | Percentage |
|---|---:|---:|
| Each forward bulk feature | 2,012,992 | 95.858% |
| Each backward bulk feature | 1,808,324 | 86.112% |

The three forward features share an identical zero/nonzero pattern. The three backward features also share an identical zero/nonzero pattern.

### 3.2 Full-dataset correlations

Full-dataset Spearman correlations were extremely high:

- Forward group: approximately 0.99971–0.99981.
- Backward group: approximately 0.98940–0.99724.

### 3.3 Conditional analysis

A conditional analysis was conducted using records in which all six bulk-statistics features were nonzero.

Records remaining: 18,378.

| Feature pair | All records | All six nonzero |
|---|---:|---:|
| Forward bytes / packets | 0.99981 | 0.32416 |
| Forward bytes / rate | 0.99971 | 0.01630 |
| Forward packets / rate | 0.99971 | 0.22754 |
| Backward bytes / packets | 0.99724 | 0.53871 |
| Backward bytes / rate | 0.99333 | 0.42520 |
| Backward packets / rate | 0.98940 | -0.21709 |

### 3.4 Interpretation and limitation

The full-dataset correlations are strongly influenced by shared zero-valued observations. The nonzero subset demonstrates distinct ranking behaviour among the bulk-statistics features.

However, the 18,378-record conditional subset is not representative of the entire dataset. It is used only as a diagnostic and should not be treated as evidence that the conditional relationships apply to the full population.

No feature should be removed solely on the basis of these conditional correlations.

## 4. Provisional conclusions

1. The URG-flag investigation identified one source-level inconsistency among 2,099,971 cleaned records. Both features are retained provisionally.
2. The bulk-statistics features have substantial zero-value concentrations and shared zero/nonzero patterns within each direction.
3. Their high full-dataset correlations are strongly influenced by shared zero-valued observations.
4. Conditional correlations provide additional diagnostic information but are based on a non-representative subset.
5. Final feature-retention decisions remain part of the broader feature-validation and model-design process.

## 5. Reproducibility and related records

Refer to the following project records for the underlying validation evidence:

- `docs/audit/cic_ids2017_feature_validation.md`
- `docs/audit/cic_ids2017_feature_inventory.csv`

The original source-level URG inconsistency was checked against the Thursday source CSV. The bulk-feature conditional analysis is a diagnostic subset analysis, not a separate training or evaluation dataset.
