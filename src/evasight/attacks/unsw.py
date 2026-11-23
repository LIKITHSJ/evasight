"""UNSW-NB15 (Argus/Zeek features): padding and delay on the attacker's (source) packets.

Relationships measured on the data: rate = (spkts+dpkts-1)/dur, sload/dload = bytes*8*(pkts-1)/pkts/dur,
smean = round(sbytes/spkts), sinpkt = source span/(spkts-1) in ms, Argus flow timeout 60 s.
Rates are rescaled rather than recomputed, so flows that deviate from a formula keep their deviation.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

MTU = 1500.0
FLOW_TIMEOUT_S = 60.0


def perturb_unsw(d: pd.DataFrame, a_pad, a_delay, eps: float, tcp) -> pd.DataFrame:
    """tcp: boolean per flow. Padding goes on payload packets only (TCP: spkts - 3)."""
    out = d.copy()
    n = d["spkts"].to_numpy(float)
    tcp = np.asarray(tcp, bool)
    k = np.where(tcp, np.maximum(n - 3, 0), n)
    sm = d["smean"].to_numpy(float)
    p = np.floor(np.asarray(a_pad) * eps * sm)
    p = np.where(k > 0, np.clip(np.minimum(p, MTU - sm), 0, None), 0.0)
    sb0 = d["sbytes"].to_numpy(float)
    sb = sb0 + p * k

    dur = d["dur"].to_numpy(float)
    gaps = np.maximum(n - 1, 0)
    t = np.where((gaps > 0) & (dur > 0), np.asarray(a_delay) * eps * d["sinpkt"].to_numpy(float) / 1000, 0.0)
    t = np.minimum(t, np.maximum(FLOW_TIMEOUT_S - dur, 0) / np.maximum(gaps, 1))
    t = np.nan_to_num(np.floor(t * 1e6) / 1e6)  # whole microseconds
    dur_new = dur + t * gaps
    f = np.divide(dur, dur_new, out=np.ones_like(dur), where=dur_new > 0)  # rates fall as the flow gets longer

    out["sbytes"] = sb
    out["smean"] = sm + np.round(p * k / np.maximum(n, 1))
    out["dur"] = dur_new
    out["sinpkt"] = d["sinpkt"] + t * 1000
    out["rate"] = d["rate"] * f
    out["sload"] = d["sload"] * np.divide(sb, sb0, out=np.ones_like(sb), where=sb0 > 0) * f
    out["dload"] = d["dload"] * f
    hs = tcp & (d["tcprtt"].to_numpy() > 0)  # handshake seen: the client's ACK is delayed too
    out["ackdat"] = d["ackdat"] + np.where(hs, t, 0.0)
    out["tcprtt"] = d["tcprtt"] + np.where(hs, t, 0.0)
    return out


def rules_unsw(d: pd.DataFrame) -> dict[str, pd.Series]:
    n = d["spkts"].clip(lower=1)
    return {
        "nonneg": (d[["sbytes", "dur", "sinpkt", "rate", "sload", "dload", "smean"]] >= 0).all(axis=1),
        "dur_le_timeout": d["dur"] <= FLOW_TIMEOUT_S + 1e-6,
        "smean_le_mtu": d["smean"] <= MTU,
        "smean_eq_bytes_per_pkt": (d["smean"] - d["sbytes"] / n).abs() <= 1,
        # No timing-gap rule: sinpkt is not tied tightly to dur in Argus output (span > dur for 4.6% and
        # mean gap > dur for 0.7% of clean flows). Delay adds to dur at least as much as to any gap anyway.
        "tcprtt_eq_synack_ackdat": (d["tcprtt"] - d["synack"] - d["ackdat"]).abs() <= 1e-4,
    }
