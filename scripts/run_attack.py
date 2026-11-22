"""Grid evasion attack against the calibrated XGBoost baseline on the CIC-IDS2017 Improved test split.

Usage: python -u scripts/run_attack.py --eps 0.1 0.25 0.5 1.0
Writes artifacts/v2/adv_eps<eps>.parquet and artifacts/v2/attack_summary.csv.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from evasight.attacks.perturb import CANON, canon
from evasight.attacks.search import grid_attack
from evasight.data.split import NON_FEATURE

ART = Path("artifacts")
TEST = Path("data/processed/cic_ids2017_improved/test.parquet")


def load_scorer(model=ART / "xgb_improved.json", cal=ART / "xgb_improved_cal.joblib"):
    bst = xgb.Booster()
    bst.load_model(model)
    c = joblib.load(cal)
    iso, feats = c["iso"], c["feats"]
    bi = bst.attr("best_iteration")
    rng = (0, int(bi) + 1) if bi is not None else (0, 0)  # use the early-stopped trees only
    back = {v: k for k, v in CANON.items() if k in feats}  # canonical names -> model names

    def score(df: pd.DataFrame) -> np.ndarray:
        X = df.rename(columns=back)[feats].astype("float32")
        return iso.predict(bst.predict(xgb.DMatrix(X), iteration_range=rng))

    return score


def summarise(cat: pd.Series, s0: np.ndarray, s: np.ndarray, eps: float) -> pd.DataFrame:
    det = s0 >= 0.5  # only flows the model caught can be evaded
    g = pd.DataFrame({"cat": cat, "detected": det, "evaded": det & (s < 0.5)})
    t = g.groupby("cat").agg(n=("detected", "size"), detected=("detected", "sum"), evaded=("evaded", "sum"))
    t.loc["ALL"] = t.sum()
    t["evasion_%"] = (100 * t.evaded / t.detected.where(t.detected > 0)).round(2)
    return t.assign(eps=eps).reset_index()


def main(eps_list, out=ART / "v2"):
    out.mkdir(parents=True, exist_ok=True)
    a = pd.read_parquet(TEST)
    a = a[a["label"] == 1].reset_index(drop=True)
    cat = a["attack_cat"].astype(str)
    flows = canon(a.drop(columns=[c for c in NON_FEATURE if c in a])).astype("float64")
    score = load_scorer()
    s0 = score(flows)
    print("check vs train log, recall@0.5 on clean attacks:")
    print(pd.Series(s0 >= 0.5).groupby(cat).mean().round(4).sort_values().to_string(), "\n")
    res = []
    for eps in eps_list:
        adv, s, _ = grid_attack(flows, score, eps)
        adv.assign(attack_cat=cat, score_orig=s0, score_adv=s).to_parquet(out / f"adv_eps{eps}.parquet")
        res.append(summarise(cat, s0, s, eps))
        print(f"eps={eps}: evasion {res[-1].iloc[-1]['evasion_%']}% of detected attacks")
    pd.concat(res).to_csv(out / "attack_summary.csv", index=False)
    print(pd.concat(res).pivot(index="cat", columns="eps", values="evasion_%").to_string())


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--eps", type=float, nargs="+", default=[0.1, 0.25, 0.5, 1.0])
    p.add_argument("--out", default="artifacts/v3")
    a = p.parse_args()
    main(a.eps, Path(a.out))
