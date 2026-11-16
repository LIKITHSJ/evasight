# Improved CIC-IDS2017 — Dataset and Feature Validation Report

**Project:** Evasight
**Dataset:** Improved CIC-IDS2017
**Validation stage:** Stage 3 — Dataset Quality and Feature Validation
**Status:** In progress
**Report purpose:** Document dataset integrity checks, feature-quality investigations, correlation analysis, and provisional feature-retention decisions.

---

## 1. Dataset Overview

### 1.1 Source information

- Dataset: Improved CIC-IDS2017
- Source archive: `CICIDS2017_improved.zip`
- Source URL: https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip
- Archive size: 343,549,013 bytes
- Locally calculated SHA-256:

`97FDB91D339E2D8CF5627F981B831E5E7E400B981C58181C451A38FD03C48883`

**Provenance limitation:** The checksum was calculated locally. It has not yet been independently compared with a publisher-provided checksum. Therefore, the dataset's provenance has been recorded, but independent authenticity verification remains pending.

### 1.2 Original dataset structure

The archive contains five CSV files:

- Monday
- Tuesday
- Wednesday
- Thursday
- Friday

Original record counts:

| Source file | Original records |
|---|---:|
| Monday | 371,624 |
| Tuesday | 322,078 |
| Wednesday | 496,641 |
| Thursday | 362,076 |
| Friday | 547,557 |
| **Total** | **2,099,976** |

The original schema contains 91 columns.

### 1.3 Label distribution

Original label categories:

- BENIGN: 1,582,566
- Attempted attack labels: 11,979
- Ordinary attack labels: 505,431

The binary classification policy maps:

- BENIGN → 0
- Labels ending in `- Attempted` → 0
- Ordinary attack labels → 1

The original attack category is preserved separately as `attack_cat`.

---

## 2. Data Cleaning and Preprocessing Validation

### 2.1 Preprocessing implementation

The preprocessing implementation is:

`src/ridsx/data/loader_cic2017_improved.py`

Processing characteristics:

- Streaming CSV processing with chunks of 100,000 records.
- Original CSV fields read as strings before numeric conversion.
- Latin-1 encoding.
- Identifier and network endpoint fields excluded from model features.
- Original attack categories retained as metadata.
- Numeric feature conversion and finite-value validation.
- Binary label mapping.
- Incremental Parquet output.
- Audit JSON generation.

### 2.2 Identifier fields removed from the model feature table

The following fields were excluded:

- ID
- Flow ID
- Src IP
- Src Port
- Dst IP
- Timestamp

`Dst Port` and `Protocol` were retained.

### 2.3 Invalid and non-finite values

Initial investigation identified ten non-finite numeric values across five records.

| Feature | Non-finite values |
|---|---:|
| Flow Bytes/s | 5 |
| Flow Packets/s | 5 |
| **Total affected records** | **5** |

The five affected records were removed rather than replacing invalid values with zero.

### 2.4 Cleaning results

| Validation item | Result |
|---|---:|
| Original records read | 2,099,976 |
| Repeated header rows | 0 |
| Invalid records removed | 5 |
| Final records written | 2,099,971 |
| Final columns | 87 |

Output files:

- `data/interim/cic_ids2017_improved.parquet`
- `data/interim/cic_ids2017_improved_audit.json`

### 2.5 Final binary label distribution

| Binary label | Records |
|---|---:|
| 0 — Benign and attempted | 1,594,540 |
| 1 — Ordinary attacks | 505,431 |
| **Total** | **2,099,971** |

No sampling, synthetic augmentation, or deduplication was performed during this preprocessing operation.

---

## 3. Schema and Label Validation

### 3.1 Schema consistency

All five original CSV files were checked for consistent column names and column ordering.

- Original schema width: 91 columns.
- Label and attempted-category fields were identified.
- No missing or blank labels were found.
- No repeated header rows were detected during preprocessing.

### 3.2 Label-category consistency

The relationship between the original `Label` and `Attempted Category` fields was checked.

Result:

- Label/category mismatches: 0
- Attempted-category records: 11,979
- Attempted-category values matched the expected attempted-label suffix.

The original attack category and attempted-category information are retained as metadata.

---

## 4. Duplicate-Record Validation

A global 64-bit row-fingerprint scan was performed across all 91 original CSV fields.

Result:

- Duplicate candidates detected: 0
- Deduplication performed: No

The cleaned dataset therefore retains all valid source records apart from the five records removed for non-finite numeric values.

**Limitation:** A fingerprint scan is an operational duplicate-screening procedure, not a mathematical proof that no duplicate records exist.

---

## 5. Missing Values and Feature Quality

### 5.1 Missing and non-finite values

The cleaned Parquet output was independently checked using PyArrow.

Results:

- Null values: 0
- Remaining non-finite numeric feature values: 0
- Final records: 2,099,971
- Final columns: 87
- Row groups: 23

The Parquet record counts, binary labels, and source-day counts were consistent with the generated audit.

### 5.2 Constant and zero-value features

Initial feature diagnostics covered 83 numeric candidate features.

Findings:

- No constant features were detected.
- No all-zero feature was detected.
- Several features have very high zero-value percentages.

High zero percentages are not automatically treated as invalid values. Their meanings must be evaluated in relation to feature definitions and network traffic characteristics.

---

## 6. Suspicious Feature-Value Investigation

### 6.1 Negative header-length values

Investigated features:

- `fwd_header_length`
- `bwd_header_length`

Negative-value counts:

| Feature | Negative records |
|---|---:|
| `fwd_header_length` | 309 |
| `bwd_header_length` | 472 |

Records where both features were negative: 188.

The negative values were checked against all five original CSV files.

The counts in the original source matched those in the cleaned Parquet output.

Therefore, these values were not introduced by the preprocessing pipeline.

**Observation:** Some negative values are close to signed 16-bit integer boundaries. An integer-overflow or source-generation issue is a possibility, but its exact cause has not been established.

**Provisional decision:** Retain the original values in the cleaned dataset. Exclude both features from the primary experimental feature set provisionally, subject to further source investigation and sensitivity analysis.
#### 6.1.1 Signed 16-bit representation diagnostic

Following the source-level verification of negative header-length values, an additional numerical investigation was conducted to examine whether the observed values were consistent with a possible signed 16-bit representation issue.

The analysis covered all 309 negative observations in `fwd_header_length` and all 472 negative observations in `bwd_header_length`.

An interesting pattern emerged: every negative observation in both features was divisible by four. In addition, adding 65,536 to each negative value produced a positive value within the range of 32,768 to 65,535.

The results are summarised below.

| Diagnostic | `fwd_header_length` | `bwd_header_length` |
|---|---:|---:|
| Negative observations | 309 | 472 |
| Values divisible by four | 309 (100%) | 472 (100%) |
| Minimum after adding 65,536 | 32,828 | 32,772 |
| Maximum after adding 65,536 | 64,988 | 65,444 |

The same pattern was observed across all five source files. All negative observations also belonged to TCP traffic (protocol 6).

This numerical pattern is consistent with a possible signed 16-bit wraparound or reinterpretation issue. In such a representation, values above the maximum signed 16-bit value can appear as negative numbers after conversion.

However, this investigation does not establish that integer overflow actually occurred. The transformed positive values are diagnostic calculations and have not been verified as the original measurements. The available evidence also does not identify the specific preprocessing, feature-generation, or data-export operation that may have introduced the negative representation.

**Interpretation:** The negative header-length values are source-originated anomalies with a numerical pattern consistent with possible signed 16-bit representation behaviour. Their precise cause remains unresolved.

**Decision:** Preserve all original values in the cleaned Parquet dataset. Continue to exclude `fwd_header_length` and `bwd_header_length` provisionally from the primary experimental feature set. Do not replace negative values with reconstructed positive values. Any future inclusion should be supported by source-level verification and sensitivity analysis.

**Limitation:** The original pre-conversion measurements and upstream feature-generation implementation have not yet been independently verified.

### 6.2 `total_tcp_flow_time`

**Investigation objective**

The `total_tcp_flow_time` feature was investigated because its distribution contained zero values and extremely large values. The objective was to determine whether these observations represented invalid measurements, preprocessing artefacts, or behaviour consistent with the feature-generation implementation.

**Distribution and protocol-level observations**

The cleaned dataset contains 2,099,971 records, comprising 1,098,771 TCP records (protocol 6) and 1,001,200 non-TCP records.

The feature contains 1,001,200 zero-valued records and 1,098,771 positive-valued records. No missing, non-finite, or negative values were observed.

All non-TCP records had `total_tcp_flow_time = 0`. The non-TCP protocol distribution was:

| Protocol | Description | Records |
|---|---|---:|
| 17 | UDP | 999,087 |
| 0 | HOPOPT / IPv6 Hop-by-Hop | 1,510 |
| 1 | ICMP | 603 |
| **Total** | | **1,001,200** |

No TCP records had a zero value.

The comparison with `flow_duration` showed:

- TCP records where both time features were equal: 1,027,390.
- TCP records where the two features differed: 71,381.

Although the features were equal for most TCP records, the differences required further investigation into whether `total_tcp_flow_time` represented a cumulative connection duration rather than only the duration of an individual flow.

**Historical source-code investigation**

The historical CICFlowMeter repository was inspected using commit `e9a987559f0e5687628b6dc385d528048c4e2312`.

In this version, `FlowFeature.java` defines the feature as:

`cum_tcp_time("Total TCP Flow Time", "TTFT")`

The corresponding field in `BasicFlow.java` is `cumulativeTcpConnectionDuration`. It is initialized to zero and exported immediately after ICMP Code and ICMP Type.

The inspected `FlowGenerator.java` implementation accumulates completed TCP flow durations. When a TCP connection continues after a flow timeout, it also adds the elapsed gap between the previous flow's last-seen timestamp and the next flow's timestamp.

The source shows that the cumulative value is updated before the feature record is written to CSV:

```java
if (flow.getProtocol() == ProtocolEnum.TCP) {
    flow = updateTcpCxnDuration(flow);
}

output.write((flow.dumpFlowBasedFeaturesEx() + LINE_SEP).getBytes());
```

Non-TCP records do not receive this update in the inspected export loop. This behaviour is consistent with the observed zero-value distribution.

**Timestamp unit**

The inspected IPv4 packet-reading paths in `PacketReader.java` assign packet timestamps using `timestampInMicros()`. `BasicFlow.getFlowDuration()` calculates the difference between the last-seen and start timestamps.

Accordingly, the historical implementation examined here represents flow duration and cumulative TCP-flow duration in microseconds. This unit interpretation is supported for the inspected IPv4 paths and should not be generalized to every possible packet-reading path without further verification.

**Extreme-value investigation**

The 20 largest values observed in the cleaned dataset were all associated with TCP (protocol 6) and the BENIGN label.

The maximum observed value was 30,290,439,669, while its corresponding `flow_duration` was only 3. If interpreted in microseconds, this cumulative value corresponds to approximately 8.41 hours.

The historical cumulative-duration implementation provides a plausible explanation for values substantially larger than the corresponding individual `flow_duration`: the cumulative feature can include durations from preceding flow segments and the gaps between those segments.

The investigated zero-valued and extreme records were also checked against the original extracted CSV files. All 15 records examined were found in their respective source files. Therefore, these values were not introduced by the Parquet loader or the preprocessing process.

**Validation interpretation**

The observed protocol distribution, the comparison with `flow_duration`, and the historical implementation provide evidence that `total_tcp_flow_time` is a protocol-dependent cumulative-duration feature rather than a direct duplicate of `flow_duration`.

The zero values for non-TCP records are consistent with the inspected implementation. The large TCP values are also compatible with cumulative durations across multiple flow segments and their intervening gaps.

However, these observations do not establish that every individual value is correct, nor do they independently establish that the inspected historical implementation was the exact version used to generate the improved CIC-IDS2017 archive.

**Provisional decision**

- Preserve the original `total_tcp_flow_time` values in the cleaned dataset.
- Do not replace zero values, cap extreme values, or reconstruct cumulative durations.
- Do not classify the feature as corrupt based solely on its distribution.
- Provisionally exclude `total_tcp_flow_time` from the primary experimental feature set until its exact dataset-generation provenance is established.
- Retain the feature for a possible sensitivity analysis, with its provenance limitation explicitly documented.

**Limitations**

The inspected historical CICFlowMeter implementation establishes the intended semantics of the feature and provides a plausible explanation for its observed distribution. However, the exact commit and runtime configuration used to generate the improved CIC-IDS2017 archive have not been independently established. The inspected source must therefore be treated as historical implementation evidence, not proof of the precise software version used for dataset generation.

## 7. Feature Schema and Candidate Feature Set

The cleaned Parquet file contains:

- 83 numeric candidate features.
- 4 metadata fields:
  - `attack_cat`
  - `attempted_category`
  - `label`
  - `source`

Total columns: 87.

The feature-validation correlation analysis used 76 candidate features after excluding seven fields provisionally or for redundancy investigation.

This reduced set is an analytical candidate set, not yet the final model feature set.

---

## 8. Feature Relationship and Redundancy Analysis

### 8.1 Near-identical and mathematically related features

The following relationships were investigated:

| Feature relationship | Finding |
|---|---|
| `average_packet_size` / `packet_length_mean` | Equal within 1e-9 tolerance across all records |
| `fwd_segment_size_avg` / `fwd_packet_length_mean` | Equal within 1e-9 tolerance across all records |
| `bwd_segment_size_avg` / `bwd_packet_length_mean` | Equal within 1e-9 tolerance across all records |
| `packet_length_variance` / `packet_length_std²` | Equal within 1e-9 tolerance across all records |

These relationships indicate substantial redundancy or deterministic dependence.

**Decision:** Preserve all original columns. Evaluate their exclusion from the final model feature set after confirming feature definitions and documenting the experimental feature policy.

### 8.2 Spearman correlation analysis

Spearman rank correlation was calculated across 76 candidate features.

Threshold used:

`|Spearman correlation| >= 0.95`

Results:

- High-correlation pairs: 55

The strongest relationships included:

| Feature pair | Absolute Spearman correlation |
|---|---:|
| `icmp_code` / `icmp_type` | 1.000000 |
| `fwd_bytes_bulk_avg` / `fwd_packet_bulk_avg` | 0.999812 |
| `fwd_bytes_bulk_avg` / `fwd_bulk_rate_avg` | 0.999714 |
| `idle_mean` / `idle_max` | 0.999103 |
| `flow_packets_s` / `fwd_packets_s` | 0.998931 |
| `fwd_packet_length_min` / `packet_length_min` | 0.998805 |
| `active_mean` / `active_max` | 0.997792 |
| `bwd_bytes_bulk_avg` / `bwd_packet_bulk_avg` | 0.997244 |

High correlation alone was not treated as sufficient evidence for feature removal.

### 8.3 Exact-value equality analysis

Exact-value comparisons were conducted for 15 selected feature pairs.

Important results:

| Feature pair | Exact equality |
|---|---:|
| `icmp_code` / `icmp_type` | 2,099,676 records |
| `fwd_bytes_bulk_avg` / `fwd_packet_bulk_avg` | 2,013,036 records |
| `fwd_bytes_bulk_avg` / `fwd_bulk_rate_avg` | 2,013,319 records |
| `idle_mean` / `idle_max` | 1,879,581 records |
| `flow_packets_s` / `fwd_packets_s` | 55,064 records |
| `fwd_packet_length_min` / `packet_length_min` | 2,094,203 records |
| `fwd_urg_flags` / `urg_flag_count` | 2,099,970 records |

These results demonstrate that high correlation does not necessarily imply exact equality.

---

## 9. Detailed Feature-Group Investigations

### 9.1 ICMP fields

Features:

- `icmp_code`
- `icmp_type`

Findings:

- Spearman correlation: 1.000.
- Exact equality: 2,099,676 records.
- Mismatches: 295 records.
- All 295 mismatches occurred under protocol 1.

Mismatch distribution:

| Attack category | Records |
|---|---:|
| BENIGN | 218 |
| Infiltration - Portscan | 53 |
| Portscan | 24 |

Common combinations:

| ICMP code | ICMP type | Records |
|---:|---:|---:|
| 1 | 3 | 127 |
| 0 | 8 | 66 |
| 9 | 8 | 53 |
| 10 | 3 | 39 |
| 0 | 11 | 9 |
| 0 | 3 | 1 |

**Interpretation:** The fields represent distinct ICMP properties. Their high correlation does not establish that they are interchangeable.

**Decision:** Retain both provisionally.
#### ICMP field validation: `icmp_code` and `icmp_type`

The feature inventory identified negative values in `icmp_code` and `icmp_type`. Both fields contained 2,099,368 records with a value of `-1`, while 603 records contained non-negative values.

A protocol-level investigation showed that all 2,099,368 records with negative values belonged to protocols 6, 17, or 0. None belonged to protocol 1 (ICMP). Conversely, all 603 records with non-negative values used protocol 1.

This pattern was identical for both fields and was observed across all five source files. The negative values were also present in both benign and attack records, indicating that the pattern was not restricted to a particular traffic class.

The observed distribution suggests that `-1` acts as a sentinel indicating that the ICMP-specific measurement is not applicable to the corresponding record. However, this interpretation has not yet been independently confirmed through the original feature-generation documentation.

The two fields were retained because their values are not interchangeable. Earlier comparisons identified records in which `icmp_code` and `icmp_type` had different values.

**Decision:** Retain both features and preserve their original values, including `-1`. Do not replace the sentinel with zero or treat these observations as invalid records. Their eventual treatment in model-specific feature sets will be considered separately.

**Limitation:** The sentinel interpretation is supported by the observed protocol distribution but remains subject to confirmation from authoritative feature documentation.

### 9.2 URG flag fields

Features:

- `fwd_urg_flags`
- `urg_flag_count`

Findings:

- Exact matches: 2,099,970.
- Mismatches: 1.

The mismatch was verified in the original Thursday CSV:

| Field | Value |
|---|---|
| Source file | `thursday.csv` |
| Source row | 423478 |
| Fwd URG Flags | 0 |
| URG Flag Count | 2 |
| Label | BENIGN |

The mismatch exists in the original source and was preserved by preprocessing.

**Decision:** Retain both provisionally and document the source-level inconsistency. Do not silently correct the record.

### 9.3 Packet-length minimum fields

Features:

- `fwd_packet_length_min`
- `packet_length_min`

Findings:

- Spearman correlation: 0.998805.
- Exact equality: 2,094,203 records.
- Unequal records: 5,768.

The forward minimum and overall flow minimum can legitimately differ because they describe different traffic directions and scopes.

**Decision:** Retain both provisionally.

### 9.4 Bulk-statistics features

Forward features:

- `fwd_bytes_bulk_avg`
- `fwd_packet_bulk_avg`
- `fwd_bulk_rate_avg`

Backward features:

- `bwd_bytes_bulk_avg`
- `bwd_packet_bulk_avg`
- `bwd_bulk_rate_avg`

Zero-value distribution:

| Feature group | Zero records | Percentage |
|---|---:|---:|
| Each forward bulk feature | 2,012,992 | 95.858% |
| Each backward bulk feature | 1,808,324 | 86.112% |

The three forward features share an identical zero/nonzero pattern. The three backward features also share an identical zero/nonzero pattern.

Full-dataset Spearman correlations were extremely high:

- Forward group: approximately 0.99971–0.99981.
- Backward group: approximately 0.98940–0.99724.

A conditional analysis was conducted using records where all six features were nonzero.

Records remaining: 18,378.

Selected correlations changed substantially:

| Feature pair | All records | All six nonzero |
|---|---:|---:|
| Forward bytes / packets | 0.99981 | 0.32416 |
| Forward bytes / rate | 0.99971 | 0.01630 |
| Forward packets / rate | 0.99971 | 0.22754 |
| Backward bytes / packets | 0.99724 | 0.53871 |
| Backward bytes / rate | 0.99333 | 0.42520 |
| Backward packets / rate | 0.98940 | -0.21709 |

**Interpretation:** Full-dataset correlations are strongly influenced by shared zero-valued observations. The nonzero subset demonstrates distinct ranking behaviour.

**Limitation:** The 18,378-record conditional subset is not representative of the entire dataset and is used only as a diagnostic.

**Decision:** Retain all six bulk features provisionally.

### 9.5 Active and idle statistics

Features:

- `active_mean`
- `active_max`
- `active_min`
- `active_std`
- `idle_mean`
- `idle_max`
- `idle_min`
- `idle_std`

Zero-value percentages:

| Feature | Zero percentage |
|---|---:|
| `active_mean` | 78.084% |
| `active_max` | 78.084% |
| `active_min` | 78.084% |
| `active_std` | 89.754% |
| `idle_mean` | 77.758% |
| `idle_max` | 77.758% |
| `idle_min` | 77.758% |
| `idle_std` | 89.505% |

A conditional correlation analysis was conducted using records where all eight features were nonzero.

Records remaining: 215,171.

Examples:

| Feature pair | All records | All eight nonzero |
|---|---:|---:|
| `active_mean` / `active_max` | 0.9978 | 0.8844 |
| `active_mean` / `active_min` | 0.9942 | 0.4181 |
| `active_max` / `active_std` | 0.6693 | 0.9723 |
| `idle_mean` / `idle_max` | 0.9991 | 0.7567 |
| `idle_mean` / `idle_min` | 0.9978 | 0.8246 |
| `idle_mean` / `idle_std` | 0.6577 | -0.2772 |

**Interpretation:** Shared zero values influence full-dataset correlation. Several features retain distinct ranking information among nonzero observations.

**Decision:** Retain all eight features provisionally pending the remaining feature-definition and redundancy checks.

### 9.6 IAT (Inter-Arrival Time) Feature Analysis

**Dataset:** Improved CIC-IDS2017
**Total records:** 2,099,971
**IAT features analysed:** 14

This analysis examined the inter-arrival time (IAT) features to understand how much overlapping information they contain and whether some features may be redundant. The investigation considered zero-value distributions, Spearman rank correlations, and exact-value comparisons. The aim was to distinguish genuine feature relationships from similarities that may arise because many records contain zero values.

#### 9.6.1 Zero-value distribution

The zero-value distribution was examined for all 14 IAT features across the complete dataset.

The proportion of zero values varied considerably between features. `flow_iat_mean` and `flow_iat_max` contained no zero values, whereas `bwd_iat_std` had the highest zero-value proportion, at approximately 60.513%.

Other features also showed substantial zero-value concentrations. For example, `fwd_iat_std` contained 55.635% zero values, while `bwd_iat_total`, `bwd_iat_mean`, and `bwd_iat_max` each contained approximately 24.628% zero values.

These differences are important because features with similar zero-value patterns can appear strongly correlated across the complete dataset, even when their nonzero observations contain different information.

#### 9.6.2 Spearman rank correlation analysis

Spearman rank correlations were calculated using two datasets:

1. **Full dataset:** All 2,099,971 records.
2. **Conditional nonzero subset:** 759,548 records in which all 14 IAT features had nonzero values.

The second analysis was performed to examine whether the relationships observed in the full dataset remained strong after records containing zero values were excluded.

Selected correlation results are presented below.

| Feature pair | Full dataset | Nonzero subset |
|---|---:|---:|
| `fwd_iat_total` / `fwd_iat_max` | 0.9955 | 0.9535 |
| `fwd_iat_total` / `fwd_iat_mean` | 0.9927 | 0.9548 |
| `bwd_iat_total` / `bwd_iat_max` | 0.9968 | 0.9644 |
| `bwd_iat_total` / `bwd_iat_mean` | 0.9933 | 0.9502 |
| `flow_iat_mean` / `fwd_iat_mean` | 0.6534 | 0.9955 |
| `flow_iat_max` / `fwd_iat_max` | 0.7706 | 0.9936 |

Several relationships remained strongly correlated in the conditional nonzero subset. In particular, the relationships between the forward and backward IAT totals and their corresponding mean or maximum values remained above 0.95.

The correlations between `flow_iat_mean` and `fwd_iat_mean`, and between `flow_iat_max` and `fwd_iat_max`, also increased substantially in the nonzero subset. This indicates that the relationships between these features differ depending on whether zero-valued observations are included.

Overall, the results show that shared zero values contribute to some of the correlations, but they do not fully explain the observed relationships. Several features continue to exhibit substantial rank similarity among records where all IAT measurements are nonzero.

#### 9.6.3 Exact-value comparison

Spearman correlation measures similarity in ranking, but it does not establish that two features contain identical values. To investigate this further, exact-value comparisons were conducted for selected IAT feature pairs across the complete dataset.

The initial comparison included all 2,099,971 records. A second comparison considered only records in which both features in the selected pair had nonzero values. This additional check was necessary because matching zero values can increase the apparent number of exact matches without demonstrating that the features are equivalent when they contain actual measurements.

The results are presented below.

**A. Exact equality across the full dataset**

| Feature pair | Exact matches | Percentage |
|---|---:|---:|
| `fwd_iat_total` / `fwd_iat_max` | 1,168,325 | 55.6353% |
| `fwd_iat_total` / `fwd_iat_mean` | 1,168,316 | 55.6349% |
| `fwd_iat_mean` / `fwd_iat_max` | 1,168,316 | 55.6349% |
| `bwd_iat_total` / `bwd_iat_max` | 1,270,798 | 60.5150% |
| `bwd_iat_total` / `bwd_iat_mean` | 1,270,702 | 60.5105% |
| `bwd_iat_mean` / `bwd_iat_max` | 1,270,749 | 60.5127% |
| `flow_iat_mean` / `flow_iat_max` | 492,706 | 23.4625% |

**B. Exact equality when both features are nonzero**

| Feature pair | Records where both are nonzero | Exact matches | Nonzero equality |
|---|---:|---:|---:|
| `fwd_iat_total` / `fwd_iat_max` | 1,634,228 | 702,582 | 42.9917% |
| `fwd_iat_total` / `fwd_iat_mean` | 1,634,228 | 702,573 | 42.9911% |
| `bwd_iat_total` / `bwd_iat_max` | 1,582,781 | 753,608 | 47.6129% |
| `bwd_iat_total` / `bwd_iat_mean` | 1,582,781 | 753,512 | 47.6068% |
| `flow_iat_mean` / `flow_iat_max` | 2,099,971 | 492,706 | 23.4625% |

The nonzero-only comparison shows that exact matches account for less than half of the eligible observations for each selected pair. For example, `fwd_iat_total` and `fwd_iat_max` were equal in 42.9917% of records where both values were nonzero, while `bwd_iat_total` and `bwd_iat_max` were equal in 47.6129% of their eligible records.

The remaining observations had different values. This confirms that the selected feature pairs are not exact duplicates across their nonzero observations.

The comparison also shows why the full-dataset equality percentages need to be interpreted carefully. For example, the full-dataset equality percentage for `fwd_iat_total` and `fwd_iat_max` was 55.6353%, but it decreased to 42.9917% when records with zero values in either feature were excluded.

For `flow_iat_mean` and `flow_iat_max`, both features were nonzero in every record. Their equality percentage therefore remained unchanged at 23.4625%.

#### 9.6.4 Interpretation of the findings

The combined correlation and exact-equality analyses provide a clearer picture of the relationships among the IAT features.

Several forward and backward IAT measurements have very high Spearman correlations, including relationships between total, mean, and maximum values. These relationships remain strong even when records containing zero values are excluded from the correlation analysis.

However, the exact-value comparisons show that these features do not consistently contain identical measurements. Even among records where both values are nonzero, more than half of the observations differ for each of the selected total-versus-maximum and total-versus-mean pairs.

This distinction is important. Strong rank correlation indicates that two features often vary in a similar order, but it does not mean that they measure the same quantity or can be substituted for one another.

The results also indicate that zero-valued observations influence some of the full-dataset relationships. Nevertheless, the high correlations observed in the conditional subset demonstrate that shared zeros are not the only explanation for the relationships.

At this stage, the findings support the presence of overlapping timing information rather than confirmed feature duplication. The available comparisons do not establish mathematical equivalence or justify removing these features.

#### 9.6.5 Provisional feature-retention decision

**Decision: Retain all 14 IAT features.**

The analysis has not provided sufficient evidence to remove any of the IAT features.

This decision is based on three observations:

1. Several feature pairs have strong rank correlations, but correlation alone does not establish redundancy.
2. The selected pairs are not exactly equal across all records where both features are nonzero.
3. The differences between the feature values indicate that they retain distinct numerical information in a substantial proportion of observations.

All 14 IAT features will therefore remain in the cleaned dataset and be available for subsequent model development.

This is a provisional retention decision rather than a claim that the features are completely independent. Their individual contribution can be examined later through model-based feature importance, SHAP explanation analysis, and controlled feature-removal experiments.

#### 9.6.6 Limitations and remaining checks

The nonzero-only correlation analysis used 759,548 records in which all 14 IAT features were nonzero. This subset provides a useful diagnostic comparison, but it is conditional on every IAT feature having a nonzero value. It may therefore represent a different traffic population from the complete dataset.

The exact-equality analysis covered five selected feature pairs and does not establish the absence of redundancy among every possible IAT feature combination.

The original feature definitions and calculation procedures should also be checked against available dataset documentation before making stronger claims about the meaning or mathematical relationships of these measurements.

**Current validation status:** Zero-value distributions, full-dataset and conditional Spearman correlations, and exact-value comparisons across the full dataset and eligible nonzero observations have been completed for the selected IAT pairs.

**Conclusion:** No IAT feature has been removed at this stage. All 14 features are retained for the next stages of dataset validation and subsequent model-based evaluation.

## 10. Provisional Feature-Retention Policy

The cleaned CIC-IDS2017 Parquet dataset retains all 83 numeric candidate features. Feature-level investigations have identified several groups requiring different treatment in the primary experimental feature set.

The following decisions are provisional and are based on the validation evidence documented in the preceding sections.

| Feature group | Provisional decision | Justification |
|---|---|---|
| ICMP Code and ICMP Type | Retain | Protocol-specific sentinel values were investigated. No evidence currently justifies excluding these features. |
| Fwd Header Length and Bwd Header Length | Exclude from primary experiments | Negative values and a possible signed 16-bit representation issue remain unresolved. Original values will be preserved. |
| URG flag features | Retain | Only one mismatch was identified, and it was present in the original source record. |
| Forward and backward bulk statistics | Retain provisionally | High full-dataset correlations were strongly influenced by shared zero values. Conditional analysis showed different relationships among non-zero records. |
| Active and idle statistics | Retain provisionally | The selected feature investigations have been completed, but final experimental suitability remains subject to the overall feature review. |
| IAT features | Retain provisionally | The selected IAT investigations are complete. All 14 features remain provisionally retained. |
| `total_tcp_flow_time` | Exclude from primary experiments; retain for sensitivity analysis | The inspected historical implementation defines this feature as a cumulative TCP-connection duration. However, the exact implementation and runtime configuration used to generate the improved CIC-IDS2017 dataset have not been independently verified. |
| Other numeric candidate features | Pending final review | Their final retention decisions have not yet been approved. |

Features excluded from the primary experimental set will remain unchanged in the cleaned dataset. No original feature values will be silently replaced, capped, or reconstructed as part of feature selection.

High correlation alone will not be treated as sufficient justification for feature removal. Decisions will consider feature definitions, data distributions, protocol dependence, redundancy, source reliability, and experimental relevance.

The final primary model feature set will be approved after the remaining validation and provenance checks have been completed.

## 11. Validation Limitations and Outstanding Work

The detailed feature-quality investigations have covered the major identified concerns, including suspicious header-length values, protocol-specific ICMP fields, potentially redundant packet-length measurements, bulk statistics, active and idle statistics, IAT features, and cumulative TCP-flow duration.

The following tasks remain before CIC-IDS2017 validation can be formally closed:

1. Verify important feature definitions and calculation procedures against authoritative dataset documentation or the relevant upstream feature-generation implementation.
2. Investigate the unresolved source-level explanation for negative forward and backward header-length values. The observed numerical pattern is consistent with a possible signed 16-bit representation issue, but this explanation has not been independently established.
3. Verify whether the historical CICFlowMeter implementation examined during the `total_tcp_flow_time` investigation corresponds to the exact implementation used to generate the improved CIC-IDS2017 archive.
4. Review and approve the final primary model feature-retention policy after the remaining provenance and feature-definition checks have been completed.
5. Independently verify the source archive checksum against a trusted publisher-provided checksum, if one is available.
6. Consolidate the validation methodology, preprocessing decisions, limitations, provenance information, and reproducibility details in the final report.

The IAT investigation is complete for the selected analyses documented in Section 9.6. All 14 IAT features are provisionally retained.

The `total_tcp_flow_time` investigation documented in Section 6.2 has established its intended cumulative-duration semantics in the inspected historical implementation. However, the exact dataset-generation version and runtime configuration remain unverified.

The current analysis does not establish that all 83 numeric candidate features are suitable for model training. Final experimental feature selection remains subject to the outstanding verification tasks and approval of the feature-retention policy.

## 12. Conclusion

The improved CIC-IDS2017 dataset has undergone initial cleaning, schema validation, label validation, duplicate screening, and several detailed feature-quality investigations.

The cleaned dataset contains 2,099,971 records and 87 columns, including 83 numeric candidate features and four metadata fields.

Several high-correlation relationships were found to be influenced by shared zero-valued observations. Source-level inconsistencies and suspicious feature values were also investigated without modifying the original raw data.

The feature-retention policy remains provisional until the remaining feature investigations are completed.

**Current research stage:** Stage 3 — Dataset Quality and Feature Validation.