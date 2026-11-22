"""Check that every processed dataset is ready for ML. Usage: python scripts/check_ready.py

Per dataset: same columns in train/val/test, no metadata or identifier columns, no NaN/Inf,
labels 0/1 with both classes, no feature vector shared between partitions, and the saved
model's features all present in the data.
"""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from evasight.data.split import NON_FEATURE

SETS = {"cic2017": ("data/processed/cic_ids2017_improved", "xgb_improved"),
        "cic2018": ("data/processed/cic_ids2018", "xgb_cic2018"),
        "unsw": ("data/processed/unsw_nb15", "xgb_unsw")}
LEAKY = (NON_FEATURE - {"label", "attack_cat"}) | {"timestamp", "ts", "flow_id", "src_ip", "dst_ip", "src_port", "id"}


def check(name: str, d: str, tag: str) -> bool:
    fails = []
    parts = {s: pd.read_parquet(Path(d) / f"{s}.parquet") for s in ("train", "val", "test")}
    cols = [list(p.columns) for p in parts.values()]
    if not all(c == cols[0] for c in cols):
        fails.append("columns differ between splits")
    feats = [c for c in cols[0] if c not in ("label", "attack_cat")]
    if set(feats) & LEAKY:
        fails.append(f"metadata/identifier columns present: {sorted(set(feats) & LEAKY)}")
    hashes = {}
    for s, p in parts.items():
        X = p[feats]
        if len(p) == 0:
            fails.append(f"{s} is empty")
        if not np.isfinite(X.to_numpy("float64")).all():
            fails.append(f"{s} has NaN/Inf")
        if not set(p["label"].unique()) <= {0, 1} or p["label"].nunique() < 2:
            fails.append(f"{s} labels are not both 0 and 1")
        hashes[s] = set(pd.util.hash_pandas_object(X, index=False))
    for a, b in (("train", "val"), ("train", "test"), ("val", "test")):
        n = len(hashes[a] & hashes[b])
        if n:
            fails.append(f"{n:,} feature vectors shared by {a} and {b}")
    model_feats = joblib.load(f"artifacts/{tag}_cal.joblib")["feats"]
    if missing := sorted(set(model_feats) - set(feats)):
        fails.append(f"model features missing from data: {missing}")
    bst = xgb.Booster()
    bst.load_model(f"artifacts/{tag}.json")
    if bst.feature_names and list(bst.feature_names) != list(model_feats):
        fails.append("model and calibrator feature lists differ")
    sizes = " / ".join(f"{len(p):,}" for p in parts.values())
    print(f"{name:8} {'PASS' if not fails else 'FAIL'}  train/val/test {sizes} | "
          f"{len(feats)} feature columns, model uses {len(model_feats)}")
    for f in fails:
        print("   -", f)
    return not fails


if __name__ == "__main__":
    ok = all([check(n, *v) for n, v in SETS.items()])
    print("\nALL DATASETS READY FOR ML" if ok else "\nNOT READY: fix the FAIL lines above")
