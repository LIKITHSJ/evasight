"""Dataset loaders: raw CSV -> cleaned Parquet (data/interim/<dataset>.parquet).

Schema of every output: float32 features + `label` (uint8: 0 benign, 1 attack)
+ `attack_cat` (category). Cleaning counts are written to data/interim/<dataset>_audit.json.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

RAW = Path("data/raw")
INTERIM = Path("data/interim")
CHUNK = 200_000


def _snake(name: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[^0-9a-z]+", "_", name).strip("_")


def _clean_label(s: pd.Series) -> pd.Series:
    # CIC labels contain a garbled en-dash in 'Web Attack - ...'; normalise to ASCII.
    return (s.astype(str).str.strip()
             .str.replace(r"[^\x20-\x7E]+", "-", regex=True)
             .str.replace(r"\s*-\s*", " - ", regex=True))


def _finish(df: pd.DataFrame, name: str, audit: dict) -> pd.DataFrame:
    audit["rows_raw"] = len(df)
    df = df.drop_duplicates()
    audit["rows_after_dedup"] = len(df)
    audit["duplicates_removed"] = audit["rows_raw"] - len(df)
    df["attack_cat"] = df["attack_cat"].astype("category")
    df = df.reset_index(drop=True)
    INTERIM.mkdir(parents=True, exist_ok=True)
    df.to_parquet(INTERIM / f"{name}.parquet", compression="zstd", index=False)
    audit["label_counts"] = df["attack_cat"].value_counts().to_dict()
    audit["attack_rate"] = float(df["label"].mean())
    (INTERIM / f"{name}_audit.json").write_text(json.dumps(audit, indent=2, default=int))
    return df


def load_cic2017() -> pd.DataFrame:
    audit = {"dataset": "cic_ids2017", "inf_nan_rows_removed": 0}
    parts = []
    for f in sorted((RAW / "cic_ids2017").glob("*.csv")):
        for chunk in pd.read_csv(f, chunksize=CHUNK, encoding="latin-1", low_memory=False):
            # pandas renames repeated headers to 'name.1'; drop those before snake-casing
            chunk = chunk.loc[:, ~chunk.columns.str.contains(r"\.\d+$")]
            chunk.columns = [_snake(c) for c in chunk.columns]
            lab = _clean_label(chunk.pop("label"))
            feats = chunk.apply(pd.to_numeric, errors="coerce").astype("float64")
            bad = ~np.isfinite(feats.to_numpy()).all(axis=1)
            audit["inf_nan_rows_removed"] += int(bad.sum())
            feats = feats.loc[~bad].astype("float32")
            feats["attack_cat"] = lab.loc[~bad].to_numpy()
            parts.append(feats)
    df = pd.concat(parts, ignore_index=True)
    df["label"] = (df["attack_cat"] != "BENIGN").astype("uint8")
    return _finish(df, "cic_ids2017", audit)


def load_unsw() -> pd.DataFrame:
    audit = {"dataset": "unsw_nb15", "inf_nan_rows_removed": 0}
    frames = []
    for f in ("UNSW_NB15_training-set.csv", "UNSW_NB15_testing-set.csv"):
        d = pd.read_csv(RAW / "unsw_nb15" / f)
        d["official_split"] = "train" if "training" in f else "test"
        frames.append(d)
    df = pd.concat(frames, ignore_index=True).drop(columns=["id"], errors="ignore")
    df.columns = [_snake(c) for c in df.columns]
    df["attack_cat"] = df["attack_cat"].astype(str).str.strip().replace({"Normal": "BENIGN"})
    df["label"] = df["label"].astype("uint8")
    cat_cols = [c for c in ("proto", "service", "state") if c in df.columns]
    for c in cat_cols:
        df[c] = df[c].astype("category")
    num = df.select_dtypes(include="number").columns.difference(["label"])
    df[num] = df[num].astype("float32")
    audit["categorical_features"] = cat_cols
    return _finish(df.drop(columns=["official_split"]), "unsw_nb15", audit)


if __name__ == "__main__":
    import sys
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("unsw", "all"):
        d = load_unsw(); print("unsw_nb15", d.shape)
    if which in ("cic2017", "all"):
        d = load_cic2017(); print("cic_ids2017", d.shape)
