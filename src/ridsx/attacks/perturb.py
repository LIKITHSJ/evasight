"""Constraint-respecting perturbation primitives for the forward-direction feature block."""
from __future__ import annotations

import numpy as np
import pandas as pd

MSS = 1460.0  # max TCP payload per packet on Ethernet


def perturb(d: pd.DataFrame, a_pad, a_delay, eps: float) -> pd.DataFrame:
    """Return a perturbed copy of d (float64 CIC-IDS2017 columns).

    a_pad, a_delay in [0, 1] (scalar or per-flow array); eps is the relative budget.
    pad:   +p bytes on every forward packet (only when every packet carries payload).
    delay: +t on every forward inter-arrival gap (only for flows with >= 2 packets).
    Derived relationships stay exact by construction.
    """
    out = d.copy()
    n = d["total_fwd_packets"]

    p = np.floor(np.asarray(a_pad) * eps * d["fwd_packet_length_mean"])
    p = np.minimum(p, np.maximum(MSS - d["fwd_packet_length_max"], 0))
    p = np.where(d["fwd_packet_length_min"] > 0, p, 0.0)
    for c in ("fwd_packet_length_min", "fwd_packet_length_mean", "fwd_packet_length_max"):
        out[c] = d[c] + p
    out["total_length_of_fwd_packets"] = d["total_length_of_fwd_packets"] + p * n

    t = np.where(n > 1, np.asarray(a_delay) * eps * d["fwd_iat_mean"], 0.0)
    for c in ("fwd_iat_mean", "fwd_iat_min", "fwd_iat_max"):
        out[c] = d[c] + t
    out["fwd_iat_total"] = d["fwd_iat_total"] + t * (n - 1)
    return out
