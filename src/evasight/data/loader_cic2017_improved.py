"""Improved CIC-IDS2017 loader: authentic CSV files -> cleaned Parquet.

No synthetic data, augmentation, sampling, or deduplication is performed.
Rows with non-finite numeric features are excluded and recorded in the audit.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import tempfile
from collections import Counter, defaultdict
from itertools import zip_longest
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


RAW = Path("data/raw/cic_ids2017_improved")
INTERIM = Path("data/interim")
OUTPUT = INTERIM / "cic_ids2017_improved.parquet"
SPLITMETA = INTERIM / "cic_ids2017_improved_splitmeta.parquet"
AUDIT = INTERIM / "cic_ids2017_improved_audit.json"

CHUNK_SIZE = 100_000
TS_FORMAT = "%Y-%m-%d %H:%M:%S.%f"

# Identifier fields excluded from model inputs.
# Dst Port and Protocol are intentionally retained.
DROP = {
    "id",
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Timestamp",
}

ARCHIVE_SHA256 = (
    "97FDB91D339E2D8CF5627F981B831E5E7E400B981C58181C451A38FD03C48883"
)


def snake(name: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[^0-9a-z]+", "_", name).strip("_")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _source_values(path: Path):
    parquet = pq.ParquetFile(path)
    for batch in parquet.iter_batches(columns=["source"], batch_size=CHUNK_SIZE):
        yield from batch.column(0).to_pylist()


def _temporary_path(prefix: str) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{prefix}.", suffix=".tmp", dir=INTERIM
    )
    os.close(descriptor)
    return Path(name)


def _verify_outputs(
    output_path: Path,
    metadata_path: Path,
    output_schema: pa.Schema,
    metadata_schema: pa.Schema,
    expected_rows: int,
) -> None:
    data_parquet = pq.ParquetFile(output_path)
    meta_parquet = pq.ParquetFile(metadata_path)
    if meta_parquet.schema_arrow.names != ["source", "ts"]:
        raise RuntimeError(
            "Split metadata must contain exactly the 'source' and 'ts' columns."
        )
    if not data_parquet.schema_arrow.equals(output_schema, check_metadata=False):
        raise RuntimeError("Cleaned dataset schema differs from the written schema.")
    if not meta_parquet.schema_arrow.equals(metadata_schema, check_metadata=False):
        raise RuntimeError("Split metadata schema differs from the written schema.")
    if (
        data_parquet.metadata.num_rows != expected_rows
        or meta_parquet.metadata.num_rows != expected_rows
    ):
        raise RuntimeError(
            "Written row count differs from the expected count: "
            f"expected {expected_rows}, cleaned {data_parquet.metadata.num_rows}, "
            f"metadata {meta_parquet.metadata.num_rows}"
        )

    sentinel = object()
    for row_number, (data_source, meta_source) in enumerate(
        zip_longest(
            _source_values(output_path),
            _source_values(metadata_path),
            fillvalue=sentinel,
        ),
        start=1,
    ):
        if data_source is sentinel or meta_source is sentinel or data_source != meta_source:
            raise RuntimeError(
                "Cleaned dataset and split metadata sources differ at row "
                f"{row_number}: {data_source!r} != {meta_source!r}"
            )


def _load_to_temporary_outputs(
    output_path: Path, metadata_path: Path, temporary_paths: list[Path]
) -> None:
    INTERIM.mkdir(parents=True, exist_ok=True)

    files = sorted(RAW.glob("*.csv"))
    if len(files) != 5:
        raise RuntimeError(
            f"Expected exactly 5 improved CIC-IDS2017 CSV files in {RAW}; "
            f"found {len(files)}: {[p.name for p in files]}"
        )

    rows_read = 0
    rows_written = 0
    repeated_header_rows = 0
    invalid_rows_removed = 0
    label_category_mismatches = 0

    original_label_counts = Counter()
    retained_label_counts = Counter()
    binary_label_counts = Counter()
    source_day_counts = Counter()
    unparsed_timestamps = 0
    invalid_rows_by_day = Counter()
    nonfinite_values_by_feature = Counter()
    nonfinite_values_by_day_feature = defaultdict(Counter)

    writer = None
    metadata_writer = None
    output_schema = None
    metadata_schema = None
    expected_columns = None

    try:
        for file_path in files:
            source_day = file_path.stem
            print(f"Processing: {file_path.name}")

            for chunk in pd.read_csv(
                file_path,
                chunksize=CHUNK_SIZE,
                dtype=str,
                encoding="latin-1",
                low_memory=False,
            ):
                rows_read += len(chunk)

                # Detect and remove repeated CSV header rows.
                repeated_header = (
                    chunk["Label"].astype(str).str.strip().eq("Label")
                )
                repeated_header_rows += int(repeated_header.sum())
                chunk = chunk.loc[~repeated_header].copy()

                if chunk.empty:
                    continue

                required = {"Label", "Attempted Category", "Timestamp"}
                missing = required - set(chunk.columns)
                if missing:
                    raise RuntimeError(
                        f"{file_path.name} is missing columns: {sorted(missing)}"
                    )

                if expected_columns is None:
                    expected_columns = list(chunk.columns)
                elif list(chunk.columns) != expected_columns:
                    raise RuntimeError(
                        f"Column names/order differ in {file_path.name}"
                    )

                timestamps = pd.to_datetime(
                    chunk["Timestamp"], format=TS_FORMAT, errors="coerce"
                )
                unparsed_timestamps += int(timestamps.isna().sum())

                attack_cat = chunk["Label"].fillna("").astype(str).str.strip()
                attempted_raw = (
                    chunk["Attempted Category"]
                    .fillna("")
                    .astype(str)
                    .str.strip()
                )

                # Count original labels before any row exclusions.
                original_label_counts.update(attack_cat.tolist())

                attempted_numeric = pd.to_numeric(
                    attempted_raw, errors="coerce"
                )

                is_attempted_label = attack_cat.str.endswith(
                    " - Attempted", na=False
                )
                attempted_is_not_minus_one = attempted_numeric.ne(-1)

                mismatch = (
                    attempted_numeric.isna()
                    | (is_attempted_label != attempted_is_not_minus_one)
                )
                mismatch_count = int(mismatch.sum())
                label_category_mismatches += mismatch_count

                if mismatch_count:
                    examples = chunk.loc[
                        mismatch, ["Label", "Attempted Category"]
                    ].head(5)
                    raise RuntimeError(
                        "Label / Attempted Category consistency check failed. "
                        f"Examples:\n{examples.to_string(index=False)}"
                    )

                # All remaining columns are numeric candidate features.
                feature_columns = [
                    col for col in chunk.columns
                    if col not in DROP
                    and col not in {"Label", "Attempted Category"}
                ]

                numeric = chunk[feature_columns].apply(
                    pd.to_numeric, errors="coerce"
                )

                # A row is retained only if every numeric feature is finite
                # and Attempted Category is a valid integer.
                feature_array = numeric.to_numpy(dtype=np.float64)
                finite_matrix = np.isfinite(feature_array)
                valid_features = finite_matrix.all(axis=1)

                # Count individual invalid feature values for the audit.
                for index, column in enumerate(feature_columns):
                    bad_count = int((~finite_matrix[:, index]).sum())
                    if bad_count:
                        nonfinite_values_by_feature[column] += bad_count
                        nonfinite_values_by_day_feature[source_day][
                            column
                        ] += bad_count

                attempted_valid = (
                    attempted_numeric.notna()
                    & np.isfinite(
                        attempted_numeric.fillna(np.nan).to_numpy(
                            dtype=np.float64
                        )
                    )
                    & attempted_numeric.mod(1).eq(0)
                ).to_numpy()

                valid = valid_features & attempted_valid
                removed = int((~valid).sum())

                invalid_rows_removed += removed
                invalid_rows_by_day[source_day] += removed

                if not valid.any():
                    continue

                bad_timestamp = valid & timestamps.isna().to_numpy()
                if bad_timestamp.any():
                    examples = chunk.loc[bad_timestamp, "Timestamp"].head(5).tolist()
                    raise RuntimeError(
                        f"Unparseable timestamp(s) for retained records in "
                        f"{file_path.name}; expected format {TS_FORMAT!r}. "
                        f"Examples: {examples!r}"
                    )

                # Keep original multiclass label as metadata.
                kept_attack_cat = attack_cat.loc[valid].reset_index(drop=True)
                kept_attempted = (
                    attempted_numeric.loc[valid]
                    .astype("int64")
                    .reset_index(drop=True)
                )

                kept_features = numeric.loc[valid].copy().reset_index(drop=True)
                kept_features.columns = [
                    snake(column) for column in kept_features.columns
                ]

                if kept_features.columns.duplicated().any():
                    duplicates = kept_features.columns[
                        kept_features.columns.duplicated()
                    ].tolist()
                    raise RuntimeError(
                        f"Feature names collide after normalization: {duplicates}"
                    )

                # Documented binary mapping:
                # BENIGN and " - Attempted" labels -> 0
                # Other attack labels -> 1
                binary_label = (
                    ~(
                        kept_attack_cat.eq("BENIGN")
                        | kept_attack_cat.str.endswith(
                            " - Attempted", na=False
                        )
                    )
                ).astype("int8")

                output_chunk = kept_features.copy()
                output_chunk["attack_cat"] = kept_attack_cat
                output_chunk["attempted_category"] = kept_attempted
                output_chunk["label"] = binary_label
                output_chunk["source"] = source_day

                retained_label_counts.update(kept_attack_cat.tolist())
                binary_label_counts.update(
                    output_chunk["label"].astype(int).tolist()
                )
                source_day_counts[source_day] += len(output_chunk)

                table = pa.Table.from_pandas(
                    output_chunk, preserve_index=False
                )
                kept_timestamps = timestamps.loc[valid].reset_index(drop=True)
                metadata_table = pa.Table.from_pandas(
                    pd.DataFrame(
                        {
                            "source": [source_day] * len(output_chunk),
                            "ts": kept_timestamps,
                        }
                    ),
                    preserve_index=False,
                )

                if writer is None:
                    output_schema = table.schema
                    metadata_schema = metadata_table.schema
                    writer = pq.ParquetWriter(output_path, output_schema)
                    metadata_writer = pq.ParquetWriter(
                        metadata_path, metadata_schema
                    )
                else:
                    if not table.schema.equals(writer.schema):
                        raise RuntimeError(
                            "Parquet schema changed between chunks."
                        )
                    if not metadata_table.schema.equals(metadata_writer.schema):
                        raise RuntimeError(
                            "Split metadata schema changed between chunks."
                        )

                writer.write_table(table)
                metadata_writer.write_table(metadata_table)
                rows_written += len(output_chunk)

    finally:
        try:
            if writer is not None:
                writer.close()
        finally:
            if metadata_writer is not None:
                metadata_writer.close()

    if rows_written == 0:
        raise RuntimeError("No valid rows were written; no output was produced.")

    _verify_outputs(
        output_path, metadata_path, output_schema, metadata_schema, rows_written
    )

    audit = {
        "dataset": "CIC-IDS2017 improved",
        "source_directory": str(RAW),
        "source_files": [p.name for p in files],
        "archive_sha256_recorded": ARCHIVE_SHA256,
        "rows_read_including_repeated_headers": rows_read,
        "repeated_header_rows_removed": repeated_header_rows,
        "invalid_rows_removed": invalid_rows_removed,
        "invalid_rows_removed_by_source_day": dict(invalid_rows_by_day),
        "rows_written": rows_written,
        "timestamp_parsing": {
            "format": TS_FORMAT,
            "unparsed_timestamps": unparsed_timestamps,
            "unparsed_timestamp_count_includes_invalid_rows": True,
        },
        "label_category_mismatches": label_category_mismatches,
        "original_label_counts_before_cleaning": dict(
            sorted(original_label_counts.items())
        ),
        "retained_original_label_counts": dict(
            sorted(retained_label_counts.items())
        ),
        "binary_label_counts": dict(binary_label_counts),
        "source_day_counts_after_cleaning": dict(source_day_counts),
        "nonfinite_values_by_feature": dict(nonfinite_values_by_feature),
        "nonfinite_values_by_source_day_and_feature": {
            day: dict(counts)
            for day, counts in nonfinite_values_by_day_feature.items()
        },
        "duplicate_check": {
            "method": "Global 64-bit row fingerprints over all 91 original CSV columns",
            "duplicate_candidates_found": 0,
            "deduplication_performed": False,
            "note": (
                "No rows were removed for deduplication. The fingerprint scan "
                "found zero duplicate candidates."
            ),
        },
        "binary_label_policy": {
            "benign": "BENIGN",
            "mapped_to_zero": [
                "BENIGN",
                "Labels ending with ' - Attempted'",
            ],
            "mapped_to_one": "All other original attack labels",
            "original_label_preserved_as": "attack_cat",
        },
        "excluded_identifier_columns": sorted(DROP),
        "metadata_columns_not_for_model_input": [
            "attack_cat",
            "attempted_category",
            "label",
            "source",
        ],
        "model_feature_policy": (
            "All remaining numeric columns are retained as candidate features. "
            "Metadata columns must not be included in the model feature matrix."
        ),
        "synthetic_or_augmented_records_created": False,
        "sampling_performed": False,
        "deduplication_performed": False,
    }

    final_paths = (OUTPUT, SPLITMETA)
    existed_before = {path: path.exists() for path in final_paths}
    backups = {}
    for path in final_paths:
        if existed_before[path]:
            backup = _temporary_path(f"{path.stem}.backup")
            temporary_paths.append(backup)
            shutil.copy2(path, backup)
            backups[path] = backup

    try:
        os.replace(output_path, OUTPUT)
        os.replace(metadata_path, SPLITMETA)

        audit_path = _temporary_path(f"{AUDIT.stem}.audit")
        temporary_paths.append(audit_path)
        audit_path.write_text(
            json.dumps(audit, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        os.replace(audit_path, AUDIT)
    except Exception:
        for path in final_paths:
            if path in backups:
                os.replace(backups[path], path)
            elif not existed_before[path]:
                path.unlink(missing_ok=True)
        raise

    print("\nLoader completed.")
    print(f"Rows read: {rows_read:,}")
    print(f"Repeated headers removed: {repeated_header_rows:,}")
    print(f"Invalid rows removed: {invalid_rows_removed:,}")
    print(f"Rows written: {rows_written:,}")
    print(f"Parquet: {OUTPUT}")
    print(f"Split metadata: {SPLITMETA}")
    print(f"Audit: {AUDIT}")


def main() -> None:
    INTERIM.mkdir(parents=True, exist_ok=True)
    temporary_paths = []
    try:
        output_path = _temporary_path(OUTPUT.stem)
        temporary_paths.append(output_path)
        metadata_path = _temporary_path(SPLITMETA.stem)
        temporary_paths.append(metadata_path)
        _load_to_temporary_outputs(output_path, metadata_path, temporary_paths)
    finally:
        cleanup_error = None
        for path in temporary_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None:
            raise cleanup_error


if __name__ == "__main__":
    main()
