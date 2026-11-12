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


def recompute_derived(orig: pd.DataFrame, pert: pd.DataFrame) -> pd.DataFrame:
    """Update features derived from the forward block after perturb(); backward side untouched.

    Assumptions (to state in the paper): the unexplained per-flow residual in
    average_packet_size is constant under perturbation; flow_duration grows by the growth
    of the forward span.
    """
    o, out = orig, pert.copy()
    nf, nb = o["total_fwd_packets"], o["total_backward_packets"]
    n = nf + nb
    lf, lb = pert["total_length_of_fwd_packets"], o["total_length_of_bwd_packets"]
    resid = o["average_packet_size"] * n - (o["total_length_of_fwd_packets"] + lb)
    out["average_packet_size"] = (lf + lb + resid) / n
    out["packet_length_mean"] = out["average_packet_size"] * n / (n + 1)
    dur = o["flow_duration"] + (pert["fwd_iat_total"] - o["fwd_iat_total"])
    sec = dur / 1e6
    out["flow_duration"] = dur
    out["flow_bytes_s"] = (lf + lb) / sec
    out["flow_packets_s"] = n / sec
    out["fwd_packets_s"] = nf / sec
    out["avg_fwd_segment_size"] = pert["fwd_packet_length_mean"]
    out["subflow_fwd_bytes"] = lf
    out["max_packet_length"] = np.maximum(pert["fwd_packet_length_max"], o["bwd_packet_length_max"])
    out["min_packet_length"] = np.minimum(
        np.where(nf > 0, pert["fwd_packet_length_min"], 1e9),
        np.where(nb > 0, o["bwd_packet_length_min"], 1e9))
    return out
