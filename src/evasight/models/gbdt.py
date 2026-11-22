"""Baseline calibrated XGBoost on the leak-aware split (train -> early stop on val -> isotonic on val)."""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score, roc_curve

D = Path("data/processed/cic_ids2017_improved")
OUT = Path("artifacts")
EXCLUDE = {"label", "attack_cat", "fwd_header_length", "bwd_header_length"}  # header: negative values, see audit


def ece(y: np.ndarray, p: np.ndarray, bins: int = 15) -> float:
    b = np.minimum((p * bins).astype(int), bins - 1)
    return float(sum((b == i).mean() * abs(y[b == i].mean() - p[b == i].mean()) for i in range(bins) if (b == i).any()))


def tpr_at_fpr(y, p, fpr_t=0.01) -> float:
    fpr, tpr, _ = roc_curve(y, p)
    return float(np.interp(fpr_t, fpr, tpr))


def main(seed: int = 0) -> None:
    tr, va, te = (pd.read_parquet(D / f"{s}.parquet") for s in ("train", "val", "test"))
    feats = [c for c in tr.columns if c not in EXCLUDE and tr[c].nunique() > 1]
    print(f"features used: {len(feats)} | train {len(tr):,} val {len(va):,} test {len(te):,}")

    clf = xgb.XGBClassifier(n_estimators=600, learning_rate=0.1, max_depth=6, subsample=0.8,
                            colsample_bytree=0.8, tree_method="hist", eval_metric="logloss",
                            early_stopping_rounds=30, random_state=seed, n_jobs=-1)
    clf.fit(tr[feats], tr["label"], eval_set=[(va[feats], va["label"])], verbose=False)
    print("best iteration:", clf.best_iteration)

    p_va = clf.predict_proba(va[feats])[:, 1]
    iso = IsotonicRegression(out_of_bounds="clip").fit(p_va, va["label"].to_numpy())
    raw = clf.predict_proba(te[feats])[:, 1]
    cal = iso.predict(raw)
    y = te["label"].to_numpy()

    print(f"\n{'':10s}{'AUC':>9s}{'PR-AUC':>9s}{'Brier':>9s}{'ECE':>9s}{'TPR@1%FPR':>11s}")
    for name, p in (("raw", raw), ("calibrated", cal)):
        print(f"{name:10s}{roc_auc_score(y, p):9.5f}{average_precision_score(y, p):9.5f}"
              f"{brier_score_loss(y, p):9.5f}{ece(y, p):9.5f}{tpr_at_fpr(y, p):11.4f}")

    pred = cal >= 0.5
    print(f"\nbenign false-positive rate @0.5: {pred[y == 0].mean():.4%}")
    per = (pd.DataFrame({"cat": te["attack_cat"], "hit": pred})
             .query("cat != 'BENIGN'").groupby("cat")["hit"].agg(["size", "mean"])
             .rename(columns={"size": "n_test", "mean": "recall@0.5"}).round(4))
    print(per.sort_values("n_test", ascending=False).to_string())

    OUT.mkdir(exist_ok=True)
    clf.save_model(OUT / "xgb_improved.json")
    joblib.dump({"iso": iso, "feats": feats}, OUT / "xgb_improved_cal.joblib")
    print("\nsaved to artifacts/")


if __name__ == "__main__":
    main()
