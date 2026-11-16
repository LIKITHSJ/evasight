"""Integrity checks on the saved split. Skipped when the processed files are absent (CI / fresh clone)."""
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

D = Path("data/processed/cic_ids2017_improved")
needed = [D / f"{s}.parquet" for s in ("train", "val", "test")]
pytestmark = pytest.mark.skipif(not all(p.exists() for p in needed), reason="processed split not built")


@pytest.fixture(scope="module")
def parts():
    return {s: pd.read_parquet(D / f"{s}.parquet") for s in ("train", "val", "test")}


def _hash(df):
    return set(pd.util.hash_pandas_object(df.drop(columns=["label", "attack_cat"]), index=False).tolist())


def test_no_feature_vector_shared_across_splits(parts):
    h = {k: _hash(v) for k, v in parts.items()}
    assert not (h["train"] & h["val"]) and not (h["train"] & h["test"]) and not (h["val"] & h["test"])


def test_labels_consistent_with_attack_cat(parts):
    for df in parts.values():
        assert ((df["attack_cat"] == "BENIGN") == (df["label"] == 0)).all()
        assert not df["attack_cat"].str.contains("Attempted").any()


def test_test_strictly_later_than_train_per_class():
    from ridsx.data.split import META, PARQ
    meta = pd.read_parquet(META)
    df = pd.read_parquet(PARQ, columns=["label", "attack_cat", "source"])
    grp = np.where(df["label"] == 1, df["attack_cat"].astype(str), "BENIGN|" + df["source"].astype(str))
    ts = meta["ts"].to_numpy()
    X = pd.read_parquet(PARQ).drop(columns=["label", "attempted_category", "attack_cat", "source"]).astype("float32")
    h = pd.util.hash_pandas_object(X, index=False).to_numpy()
    first = pd.DataFrame({"h": h, "g": grp, "ts": ts}).sort_values("ts", kind="stable").drop_duplicates("h")
    split_h = {s: pd.util.hash_pandas_object(pd.read_parquet(D / f"{s}.parquet").drop(columns=["label", "attack_cat"]),
                                             index=False) for s in ("train", "test")}
    first["split"] = np.where(first["h"].isin(split_h["train"]), "train",
                              np.where(first["h"].isin(split_h["test"]), "test", "other"))
    for g, d in first[first["split"] != "other"].groupby("g"):
        tr, te = d.loc[d["split"] == "train", "ts"], d.loc[d["split"] == "test", "ts"]
        if len(tr) and len(te):
            assert tr.max() < te.min(), f"time leak in {g}: train reaches {tr.max()}, test starts {te.min()}"
