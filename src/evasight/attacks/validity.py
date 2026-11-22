"""Validity rules for CIC-IDS2017 flows. Each rule returns a boolean Series (True = valid)."""

from __future__ import annotations

import pyarrow.parquet as pq
from evasight.attacks.perturb import CANON, canon

import numpy as np
import pandas as pd

COLS = [
    "total_fwd_packets", "total_length_of_fwd_packets", "fwd_packet_length_max",
    "fwd_packet_length_min", "fwd_packet_length_mean", "fwd_packet_length_std",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "act_data_pkt_fwd", "min_seg_size_forward", "init_win_bytes_forward", "fwd_header_length",
]


def _not_tcp(d: pd.DataFrame) -> pd.Series:
    """TCP-only rules pass for other protocols; the original release has no protocol column."""
    return d["protocol"].ne(6) if "protocol" in d else pd.Series(False, index=d.index)


def rules(d: pd.DataFrame) -> dict[str, pd.Series]:
    n, tot = d["total_fwd_packets"], d["total_length_of_fwd_packets"]
    lmin, lmean, lmax = (d[f"fwd_packet_length_{k}"] for k in ("min", "mean", "max"))
    imin, imean, imax = (d[f"fwd_iat_{k}"] for k in ("min", "mean", "max"))
    return {
        "packets_ge_1": n >= 1,
        "nonneg_counts": (d[["total_fwd_packets", "total_length_of_fwd_packets",
                             "act_data_pkt_fwd", "fwd_header_length"]] >= 0).all(axis=1),
        "init_win_valid": (d["init_win_bytes_forward"] == -1) | ((d["init_win_bytes_forward"] >= 0) & (d["init_win_bytes_forward"] <= 65535 * 2**14)),
        "len_min_le_mean_le_max": (lmin <= lmean + 1e-3) & (lmean <= lmax + 1e-3),
        "iat_min_le_mean_le_max": (imin <= imean + 1e-3) & (imean <= imax + 1e-3),
        "iat_total_ge_max": d["fwd_iat_total"] >= imax - 1,
        "std_nonneg": (d[["fwd_packet_length_std", "fwd_iat_std"]] >= 0).all(axis=1),
        "total_len_eq_mean_x_n": pd.Series(
            np.isclose(tot, lmean * n, rtol=1e-2, atol=1.0), index=d.index),
        "active_le_total_packets": d["act_data_pkt_fwd"] <= n,
        "iat_total_eq_mean_x_gaps": (n <= 1) | pd.Series(
            np.isclose(d["fwd_iat_total"], imean * (n - 1), rtol=1e-2, atol=1.0), index=d.index),
        "len_std_popoviciu": (n <= 1) | (d["fwd_packet_length_std"] <= (lmax - lmin) / 2
                                         * np.sqrt(n / (n - 1).clip(lower=1)) + 1e-3),
        "header_per_packet_20_60": _not_tcp(d) | (d["fwd_header_length"] / n).between(20, 60),
        "min_seg_size_valid": _not_tcp(d) | (d["min_seg_size_forward"].between(20, 60)
                              & (d["min_seg_size_forward"] % 4 == 0)),
    }


def calibrate(parquet: str = "data/processed/cic_ids2017_improved/train.parquet") -> pd.DataFrame:
    names = set(pq.read_schema(parquet).names)
    back = {v: k for k, v in CANON.items() if k in names}  # file may use Improved names
    d = canon(pd.read_parquet(parquet, columns=[back.get(c, c) for c in COLS] + ["label"] + (["protocol"] if "protocol" in names else []))).astype("float64")
    lab = d.pop("label").astype(bool)
    rows = {}
    for name, ok in rules(d).items():
        bad = ~ok
        rows[name] = {"all_%": 100 * bad.mean(), "benign_%": 100 * bad[~lab].mean(),
                      "attack_%": 100 * bad[lab].mean()}
    return pd.DataFrame(rows).T.round(3)


if __name__ == "__main__":
    print(calibrate().to_string())
