"""Constraint-respecting perturbation primitives for the forward-direction feature block."""
from __future__ import annotations

import numpy as np
import pandas as pd

MSS = 1460.0  # max TCP payload per packet on Ethernet

# Improved CIC-IDS2017 column names -> canonical names used by the attack code.
CANON = {"total_fwd_packet": "total_fwd_packets", "total_bwd_packets": "total_backward_packets",
         "total_length_of_fwd_packet": "total_length_of_fwd_packets",
         "total_length_of_bwd_packet": "total_length_of_bwd_packets",
         "fwd_segment_size_avg": "avg_fwd_segment_size",
         "packet_length_max": "max_packet_length", "packet_length_min": "min_packet_length",
         "fwd_act_data_pkts": "act_data_pkt_fwd",
         "fwd_init_win_bytes": "init_win_bytes_forward", "fwd_seg_size_min": "min_seg_size_forward"}


def canon(df: pd.DataFrame) -> pd.DataFrame:
    return df.rename(columns=CANON)


def perturb(d: pd.DataFrame, a_pad, a_delay, eps: float) -> pd.DataFrame:
    """Return a perturbed copy of d (float64 CIC-IDS2017 columns).

    a_pad, a_delay in [0, 1] (scalar or per-flow array); eps is the relative budget.
    pad:   +p bytes on every forward packet (only when every packet carries payload).
    delay: +t on every forward inter-arrival gap (only for flows with >= 2 packets).
    Derived relationships stay exact by construction.
    """
    out = d.copy()
    n = d["total_fwd_packets"]

    k = d["act_data_pkt_fwd"]  # forward packets that carry payload; SYN/ACK stay empty
    lf = d["total_length_of_fwd_packets"]
    # Budget: eps * mean payload of a data packet; capped so no packet exceeds the MSS.
    p = np.floor(np.asarray(a_pad) * eps * lf / k.where(k > 0))
    p = np.minimum(p, np.maximum(MSS - d["fwd_packet_length_max"], 0))
    p = np.nan_to_num(np.asarray(p, dtype=float))  # k == 0 -> no payload -> no padding
    lf_new = lf + p * k
    out["total_length_of_fwd_packets"] = lf_new
    out["fwd_packet_length_mean"] = lf_new / n
    out["fwd_packet_length_max"] = d["fwd_packet_length_max"] + p
    out["fwd_packet_length_min"] = d["fwd_packet_length_min"] + np.where(k == n, p, 0.0)

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
    # Improved release: subflow_fwd_bytes != total fwd bytes (often 0, ~15x smaller otherwise).
    # Assumption: it scales in proportion to total forward bytes; zeros stay zero.
    ratio = lf / o["total_length_of_fwd_packets"].where(lambda s: s > 0)
    out["subflow_fwd_bytes"] = (o["subflow_fwd_bytes"] * ratio).fillna(o["subflow_fwd_bytes"])
    out["max_packet_length"] = np.maximum(pert["fwd_packet_length_max"], o["bwd_packet_length_max"])
    out["min_packet_length"] = np.minimum(
        np.where(nf > 0, pert["fwd_packet_length_min"], 1e9),
        np.where(nb > 0, o["bwd_packet_length_min"], 1e9))
    return out
