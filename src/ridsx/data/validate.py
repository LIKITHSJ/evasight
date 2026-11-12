"""Independent validation of the cleaned Parquet datasets in data/interim."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

INTERIM = Path("data/interim")
RARE = 100
DATASETS = (("cic_ids2017", "rows_after_dedup"), ("unsw_nb15", "rows_after_dedup"),
            ("cic_ids2018", "rows_written"))


def validate(name: str, rows_key: str) -> dict:
    df = pd.read_parquet(INTERIM / f"{name}.parquet")
    audit = json.loads((INTERIM / f"{name}_audit.json").read_text())
    feats = [c for c in df.columns if c not in ("label", "attack_cat", "source")]
    num = [c for c in feats if pd.api.types.is_numeric_dtype(df[c])]
    cat = df["attack_cat"].astype(str)
    counts = cat.value_counts()
    r = {"dataset": name, "rows": len(df), "features": len(feats)}
    r["rows_match_audit"] = len(df) == audit[rows_key]
    r["class_counts_match_audit"] = (
        {k: int(v) for k, v in counts.items()}
        == {k: int(v) for k, v in audit["label_counts"].items()})
    r["non_finite_values"] = int(sum(
        (~np.isfinite(df[c].to_numpy(dtype="float64"))).sum() for c in num))
    r["label_mismatch"] = int(
        (df["label"].to_numpy() != (cat != "BENIGN").to_numpy().astype("uint8")).sum())
    r["duplicate_rows"] = int(pd.util.hash_pandas_object(
        df[feats + ["attack_cat"]], index=False).duplicated().sum())
    r["non_float32_numeric"] = [c for c in num if df[c].dtype != np.float32]
    neg = {c: int((df[c] < 0).sum()) for c in num if not ("init" in c and "win" in c)}
    r["negative_values"] = {c: n for c, n in neg.items() if n}
    r["constant_columns"] = [c for c in num if df[c].min() == df[c].max()]
    r["rare_classes"] = {k: int(v) for k, v in counts.items() if v < RARE}
    r["attack_rate"] = round(float(df["label"].mean()), 4)
    return r


def main() -> None:
    hard = ("rows_match_audit", "class_counts_match_audit")
    for name, key in DATASETS:
        r = validate(name, key)
        ok = (all(r[k] for k in hard) and r["non_finite_values"] == 0
              and r["label_mismatch"] == 0 and r["duplicate_rows"] == 0)
        print(f"\n=== {name}: {'PASS' if ok else 'FAIL'} ===")
        print(json.dumps(r, indent=1))


if __name__ == "__main__":
    main()
