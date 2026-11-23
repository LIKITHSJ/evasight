# Evasight Dataset Decision Register

**Decision date:** 22 November 2026

**Register status:** CIC-IDS2017, CIC-IDS2018, and UNSW-NB15 policies approved

**Scope:** Dataset selection, preprocessing, feature eligibility, duplicate handling, and evaluation requirements for the Evasight NIDS research.

## 1. Objective and scope

Evasight studies whether SHAP and LIME explanations for a network intrusion detector remain stable under constraint-respecting adversarial perturbations, and whether explanation instability can help detect evasion. This register records approved dataset policies and separates them from evidence, interpretation, unresolved questions, and recommendations awaiting approval.

This document does not authorize a preprocessing run, code change, dataset change, relabeling, filtering, deduplication, split creation, or artifact overwrite. Existing raw and interim artifacts remain preserved. Any future artifact must have a distinct path and record its source, preprocessing configuration, seed, row counts, and checksums.

## 2. Evidence basis and terminology

The register draws on the repository audit records, loader implementations, and the completed read-only raw-source investigation. Relevant records include:

- `docs/audit/cic_ids2017_audit.json` and `data/interim/cic_ids2017_audit.json`
- `docs/audit/cic_ids2018_audit.json` and `data/interim/cic_ids2018_audit.json`
- `docs/audit/unsw_nb15_audit.json` and `data/interim/unsw_nb15_audit.json`
- `docs/audit/cic_ids2017_feature_validation.md`
- `docs/audit/cic_ids2017_feature_inventory.csv`
- `docs/audit/feature_analysis.md` and `docs/audit/validity_notes.md`
- `src/ridsx/data/loaders.py`
- `src/ridsx/data/loader_cic2017_improved.py`
- `src/ridsx/data/loader_cic2018.py`
- `docs/checksums.txt` and `docs/checksums_2018.txt`

**Confirmed finding** means the result was observed in the available artifact or independently calculated from the available source files. **Interpretation** is a research implication consistent with the evidence but not proven as the cause. **Unresolved** means the available files do not establish the answer or a required policy detail remains undecided.

Hash equality identifies candidate matches; it is not, by itself, proof of row equality. Where noted below, candidates were compared directly. Feature-vector equality does not establish identity of an underlying network flow.

## 3. CIC-IDS2018 — approved policy

### 3.1 Primary comparison dataset

- Preserve all valid attack records.
- Preserve the existing 10% seeded benign sample using seed 42.
- Do not globally deduplicate the primary comparison dataset.
- Preserve original labels and attack-category values.
- Preserve repeated feature vectors and conflicting labels; identify and report their groups and frequencies.
- Do not infer that equal feature vectors represent the same network flow.
- Use group-aware evaluation so identical feature vectors cannot occur in both training and testing partitions.
- Report capture-day and category distributions, row counts, and class prevalence for each evaluated deduplication policy.

### 3.2 Comparison experiments

- Retain the existing globally deduplicated artifact unchanged as a comparison artifact.
- Evaluate within-capture-day deduplication as a separate sensitivity experiment.
- Give each future artifact a new, distinct path. Do not overwrite the existing Parquet or audit JSON.

### 3.3 Evidence and rationale

**Confirmed:** The existing loader uses seed 42 and a 10% benign sample, then globally deduplicates hashes over float32 features plus `attack_cat`. The existing audit records 16,233,002 rows read, 59 repeated headers, 95,760 invalid rows, 1,598,383 deduplication removals, and 2,486,278 retained rows. The audit reports a natural attack rate of 17.02% and an output attack rate of 54.33%.

**Confirmed:** An independent in-memory replay reproduced the sampling and loader totals. It attributed 1,396,131 removals to attack records and 202,252 to sampled benign records. The replay directly compared float32 feature values and category for hash-matched duplicate candidates and found no mismatches. The loader itself relies on hashes and does not perform that direct equality check.

**Confirmed:** Removals vary by day and category. Examples include 193,301 of 193,354 sampled FTP-BruteForce records removed on Wednesday-14-02, and 139,835 of 139,890 sampled DoS attacks-SlowHTTPTest records removed on Friday-16-02.

**Confirmed:** A feature vector shared by Friday-02-03 BENIGN at raw CSV line 564537 and Wednesday-28-02 Infilteration at line 490088 has different timestamps and conflicting labels. The raw CIC-IDS2018 files inspected contain a timestamp but no Flow ID, source IP, source port, or destination IP fields. The available source therefore establishes distinct CSV rows and timestamps, but not the identity or relationship of the underlying network flows.

**Interpretation:** Global deduplication after benign sampling materially changes category, day, and class representation. The output attack prevalence should not be presented as natural capture prevalence.

### 3.4 Reproducibility requirements

For every newly authorized artifact, preserve the raw and existing interim artifacts and record the exact configuration, seed, source checksums, row counts before and after each transformation, category/day distributions, and output checksum. The existing global-dedup artifact and its audit are historical comparison records and must not be rewritten.

## 4. CIC-IDS2017 — approved policy, Option C

### 4.1 Separate experiments

Run and report three separate experiments:

1. Original CIC-IDS2017 using its original 77-feature schema.
2. Improved CIC-IDS2017 using the documented common 76-feature schema mapping.
3. Improved CIC-IDS2017 using additional features that are explicitly found eligible after further review.

Keep original and improved variants separate. Do not combine their rows into one dataset. Document feature mappings. Keep identifiers and target metadata out of model inputs. Preserve identifiers where available in a provenance/grouping record. Report conflicting feature-vector groups.

### 4.2 Feature-schema distinction

The **common 76-feature schema mapping** is the alignment between the original and improved variants: 57 same-name feature columns plus 19 documented name aliases. It is not an instruction to equate semantically uncertain fields. In particular, `cwe_flag_count` and `cwr_flag_count` are not mapped to one another without independent feature-definition evidence.

This common mapping is distinct from the **separate 76-feature validation subset** discussed in `cic_ids2017_feature_validation.md`. That validation subset was formed after excluding seven fields provisionally or for redundancy analysis. Its matching count of 76 does not make it the common schema mapping, and its exclusions do not define the approved three-experiment policy.

The improved-only feature eligibility list is **pending further review**. No improved-only feature is automatically approved for experiment 3. In particular, `total_tcp_flow_time` remains subject to the provenance limitation and provisional exclusion described in the feature-validation report. Other features with unresolved validity or semantics also require review before inclusion.

### 4.3 Attempted records

- Preserve the current binary labels in the primary reproducibility experiment.
- Run a separate sensitivity experiment excluding the 11,979 attempted records.
- Do not relabel attempted records without independent evidence and explicit approval.
- Keep `attempted_category` out of model inputs.

### 4.4 Duplicate and provenance handling

Do not silently remove repeated feature vectors or assume they identify the same flow. Report conflicting feature-vector groups. Keep raw identifiers in provenance where present, while excluding identifiers and target metadata from model input matrices. Any future group-aware split must document its grouping key and preserve label ambiguity for review.

### 4.5 Evidence and rationale

**Confirmed:** The original CIC-IDS2017 scan counted 2,830,743 parsed rows, excluded 2,867 nonfinite rows, and deduplicated 329,896 occurrences among 2,827,876 valid rows to produce 2,497,980 rows. The audit field named `rows_raw` records the valid-row count after nonfinite exclusion, which explains the apparent accounting discrepancy.

**Confirmed:** At least one original-variant feature vector is identical across all 77 numeric features after float32 conversion but has conflicting raw labels: PortScan at `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`, CSV line 108513, and BENIGN at `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`, line 50345. The original CSVs do not retain the flow identifiers needed to determine whether these are the same underlying flow.

**Confirmed:** In the improved variant, matching retained feature vectors can trace to different raw Flow IDs, source ports, and timestamps. For example, Friday raw line 153697 and Thursday raw line 190337 have equal retained numeric features but different identifiers and labels. The improved loader removes identifiers from the model-feature table and performs no row deduplication.

**Confirmed:** The improved audit records 2,099,971 retained rows, 83 numeric candidate features, and four metadata fields. Its raw schema has 91 columns. The original and improved feature values use different numeric storage types, so comparisons must follow the documented mapping and preserve each source variant's processing.

**Unresolved:** The provenance investigation found extreme negative and overflow-like values in original CIC-IDS2017, including negative duration/rate and header/segment-size values. Their precise source-level cause is not established by the CSVs alone. Original PCAP-level diagnosis and authoritative confirmation of feature-generation behavior remain outstanding.

**Interpretation:** The improved source identifiers show that equal cleaned feature vectors can come from distinct raw records. Consequently, feature-vector equality is useful for group-aware evaluation but is not a basis for claiming that the observations are the same flow.

### 4.6 Unresolved 35-flow `fwd_header_length` conflict

`docs/audit/validity_notes.md` states that 35 flows have negative `fwd_header_length` values and says they are “to be dropped in the loader.” The feature-validation report instead says to preserve original values in the cleaned dataset and provisionally exclude the feature from primary experiments. These statements conflict about whether records or only a feature are excluded.

**Status: unresolved.** This register does not authorize dropping those 35 records, changing their values, or excluding them from a dataset. The discrepancy must be reviewed and clarified by the research owners before any related preprocessing or feature-selection action.

## 5. UNSW-NB15 — approved policy

The research owner approved the following policies on 22 November 2026:

1. Maintain both the official-split benchmark and a separately reported group-aware evaluation.
2. Preserve the existing official-split artifact, including its 545 residual feature-vector overlap groups. Disclose their conflicting binary and multiclass labels.
3. In the group-aware evaluation, keep each identical feature-vector group entirely within one partition.
4. Preserve original binary and multiclass labels. Do not automatically delete ambiguous groups or relabel records.
5. Retain float32 for the existing-artifact reproduction baseline.
6. Evaluate integer-precision preservation for `stcpb` and `dtcpb` in a separate sensitivity experiment.

This policy approves evaluation and reporting choices. It does not authorize preprocessing changes or generation of artifacts.

### 5.1 Evidence and recommendation for review

**Confirmed:** The existing audit records 93,988 within-split duplicate removals and 940 cross-split complete-record removals. The final artifact contains 106,800 training rows and 55,945 testing rows. A read-only in-memory replay of the loader reproduced those totals.

**Confirmed:** The original source splits have 1,302 shared feature-vector groups before the loader's complete-record cleanup. Direct value comparison of the hash-matched source feature rows found no mismatches. The existing cleaned artifact retains 545 shared feature-vector groups: 277 with conflicting binary labels, and 268 additional groups with consistent binary labels but differing multiclass categories. The 940 complete-record matches were also directly compared across source fields excluding the assigned row `id`; no mismatches were found.

**Confirmed:** Float32 conversion created no additional shared train/test feature-vector groups in the source-precision comparison. It did round 118,156 of 257,673 `stcpb` values and 118,167 of 257,673 `dtcpb` values, approximately 46% for each field. The number of distinct values fell from 114,473 to 114,135 for `stcpb`, and from 114,187 to 113,869 for `dtcpb`.

**Approved policy:** Retain the existing artifact as the official-split reproducibility baseline and also report a separate group-aware evaluation. Preserve and disclose the 545 residual overlap groups and their conflicting binary and multiclass labels in the official track. In the group-aware track, keep each identical feature-vector group wholly within one partition. Preserve original labels without automatic relabeling or deleting ambiguous groups. Use the existing float32 artifact for the reproduction baseline and evaluate integer-precision preservation for `stcpb` and `dtcpb` in a separate sensitivity experiment.

**Rationale:** The official track maintains comparability with the existing dataset protocol and artifact. The group-aware track measures generalization without identical feature vectors crossing partitions. Preserving contradictory labels exposes ambiguity rather than hiding it. A precision comparison is warranted because many sequence-counter values change under float32, even though this conversion did not create additional cross-split vector groups in the measured data.

**Limitations:** These results establish equality of available source feature values, not identity of the underlying network connection. The `id` field is an assigned row identifier and was excluded from feature comparisons. No label correction or flow-identity inference is approved.

## 6. Cross-dataset principles

- Use authentic, traceable source datasets; do not create synthetic records.
- Preserve raw originals, existing interim artifacts, and their checksums.
- Preserve labels and category values unless a separately approved policy explicitly authorizes a change supported by independent evidence.
- Document every sampling, filtering, deduplication, conversion, and split operation, including order, seed, input/output row counts, and checksums.
- Do not treat hash equality as record equality without direct comparison.
- Do not infer underlying flow identity from feature-vector equality.
- Keep identifiers, source metadata, labels, categories, and other target metadata out of model inputs unless a separately reviewed experiment explicitly authorizes a field.
- Report confirmed evidence separately from interpretations and unresolved explanations.
- Keep comparison policies as separate, named experiments and artifacts; do not overwrite existing results.

## 7. Actions prohibited without separate approval

This register alone does not authorize any code or data operation. Until separate approval is recorded, do not:

- Modify, regenerate, overwrite, or delete raw or interim datasets, audit JSONs, or checksum records.
- Silently sample, filter, deduplicate, remove ambiguous groups, or change labels.
- Drop the 35 negative-`fwd_header_length` records or otherwise resolve that conflict by assumption.
- Change, create, or replace train/test splits or evaluation group assignments.
- Include uncertain improved-only CIC-IDS2017 features in a model input set by default.
- Implement UNSW-NB15 preprocessing or generate artifacts based solely on this policy decision; separate implementation authorization is required.
- Stage, commit, push, merge, rebase, stash, or restore changes as part of a policy decision.

Any new approved artifact must use a new path and retain a reproducible record of source checksums, preprocessing configuration, seeds, row counts, and output checksum.

## 8. Future approval log

Add future decisions only after explicit research-owner approval. Each entry should include the date, decision identifier, dataset and experiment scope, exact approved action, evidence reviewed, approver(s), implementation authorization (if any), artifact path(s), preprocessing configuration and seed, row counts, checksums, and status.

| Date | Decision ID | Dataset / scope | Decision and evidence | Approver(s) | Implementation authorized? | Status |
|---|---|---|---|---|---|---|
| 2026-11-22 | 3.1 | CIC-IDS2018 | Primary sampled non-global-dedup comparison; retain existing global-dedup comparison; within-day dedup as separate sensitivity; preserve labels and repeated vectors; group-aware evaluation and distribution reporting. | Research review | No preprocessing change authorized | Approved policy |
| 2026-11-22 | 3.1 | CIC-IDS2017 | Option C: separate original, common-mapping improved, and eligible-additional-feature experiments; preserve current attempted labels in primary and run attempted-record exclusion sensitivity; feature eligibility details remain subject to review. | Research review | No preprocessing change authorized | Approved policy |
| 2026-11-22 | — | UNSW-NB15 | Maintain official-split and group-aware evaluations; preserve the existing artifact and 545 residual overlap groups with conflicting labels; keep each identical vector group in one group-aware partition; preserve labels; retain float32 for artifact reproduction and evaluate integer precision for `stcpb`/`dtcpb` separately. | Research owner | No preprocessing change authorized | Approved policy |
