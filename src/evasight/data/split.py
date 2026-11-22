"""Leak-aware split of the improved CIC-IDS2017: drop 'Attempted', dedup, per-class time blocks."""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

PARQ = Path("data/interim/cic_ids2017_improved.parquet")
META = Path("data/interim/cic_ids2017_improved_splitmeta.parquet")
OUT = Path("data/processed/cic_ids2017_improved")
NON_FEATURE = {"label", "attempted_category", "attack_cat", "source"}


def build(frac: tuple[float, float] = (0.70, 0.85), gap_s: float = 60.0, gap_span: float = 0.02,
          max_purge: float = 0.01, parq: Path = PARQ, meta_path: Path = META, out_dir: Path = OUT):
    df = pd.read_parquet(parq)
    meta = pd.read_parquet(meta_path)
    assert len(df) == len(meta) and (df["source"].to_numpy() == meta["source"].to_numpy()).all()
    feats = [c for c in df.columns if c not in NON_FEATURE]
    X = df[feats].astype("float32")
    y = df["label"].to_numpy().astype("int8")
    cat = df["attack_cat"].astype(str).to_numpy()
    src = df["source"].astype(str).to_numpy()
    ts = meta["ts"]
    del df

    att = pd.Series(cat).str.contains("Attempted").to_numpy()
    h = pd.util.hash_pandas_object(X, index=False).to_numpy()
    sub = pd.DataFrame({"h": h, "y": y, "ts": ts.to_numpy()})[~att]
    conflict = sub.groupby("h")["y"].nunique()
    conflict = conflict.index[conflict > 1]
    n0 = len(sub)
    sub = sub[~sub["h"].isin(conflict)]
    n1 = len(sub)
    sub = sub.sort_values("ts", kind="stable").drop_duplicates("h")
    idx = sub.index.to_numpy()          # original row positions of the kept rows
    print(f"rows {len(y):,} | attempted dropped {att.sum():,} | conflicting-label dropped {n0 - n1:,} "
          f"| duplicates dropped {n1 - len(sub):,} | kept {len(sub):,}")

    sec = (sub["ts"] - sub["ts"].min()).dt.total_seconds().to_numpy()
    grp = np.where(y[idx] == 1, cat[idx], "BENIGN|" + src[idx])
    sp = np.full(len(idx), -1, dtype=np.int8)           # -1 = purged
    for g in np.unique(grp):
        pos = np.flatnonzero(grp == g)
        t = sec[pos]
        s_ = np.sort(t)
        n = len(s_)
        i1, i2 = int(n * frac[0]), min(int(n * frac[1]), n - 1)
        c1, c2 = s_[i1], s_[i2]
        gap = min(gap_s, gap_span * (s_[-1] - s_[0]))
        # Purge only flows just before a cut: within `gap` seconds AND among the
        # nearest max_purge * n flows by time rank (bursty classes would otherwise vanish).
        r = np.empty(n, dtype=np.int64)
        r[np.argsort(t, kind="stable")] = np.arange(n)
        m = max(1, int(max_purge * n))
        near1 = (t < c1) & (t >= c1 - gap) & (r >= i1 - m)
        near2 = (t < c2) & (t >= c2 - gap) & (r >= i2 - m)
        sp[pos] = np.where(t >= c2, 2,
                           np.where(t >= c1, np.where(near2, -1, 1), np.where(near1, -1, 0)))

    out_dir.mkdir(parents=True, exist_ok=True)
    for i, name in enumerate(("train", "val", "test")):
        rows = idx[sp == i]
        out = X.iloc[rows].copy()
        out["label"] = y[rows]
        out["attack_cat"] = cat[rows]
        out.to_parquet(out_dir / f"{name}.parquet", index=False)

    rep = pd.crosstab(cat[idx], np.where(sp < 0, "purged", np.array(["train", "val", "test"])[sp.clip(0)]))
    print(rep[[c for c in ("train", "val", "test", "purged") if c in rep]].to_string())
    print(f"\npurged total: {(sp < 0).sum():,}")
    return rep


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["cic2018"]:
        build(parq=Path("data/interim/cic_ids2018_v2.parquet"),
              meta_path=Path("data/interim/cic_ids2018_v2_splitmeta.parquet"),
              out_dir=Path("data/processed/cic_ids2018"))
    else:
        build()
