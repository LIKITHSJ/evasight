"""Draft feature-controllability table for CIC-IDS2017 (rules are suggestions; review each row)."""
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

import pyarrow.parquet as pq

FREE = {
    "total_fwd_packets", "total_length_of_fwd_packets", "fwd_packet_length_max",
    "fwd_packet_length_min", "fwd_packet_length_mean", "fwd_packet_length_std",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "init_win_bytes_forward", "act_data_pkt_fwd", "min_seg_size_forward", "fwd_header_length",
}
FLAG_WORDS = ("flag_count", "_flags")
DERIVED_PREFIX = (
    "flow_", "packet_length_", "max_packet_length", "min_packet_length", "average_packet_size",
    "down_up_ratio", "subflow_", "active_", "idle_", "fwd_packets_s", "avg_fwd_segment_size",
    "fwd_avg_",
)


def classify(name: str) -> tuple[str, str]:
    if name == "destination_port":
        return "fixed", "service chosen by the attack; changing it changes the target"
    if "bwd" in name or "backward" in name or name.startswith("avg_bwd"):
        return "fixed", "backward direction is produced by the victim, not the attacker"
    if any(w in name for w in FLAG_WORDS):
        return "fixed", "TCP flag semantics define the attack behaviour"
    if name in FREE:
        return "free", "set by the attacker's own forward packets"
    if name.startswith(DERIVED_PREFIX):
        return "derived", "computed from other features; recompute after perturbation"
    return "review", "no rule matched; decide manually"


def build(parquet="data/interim/cic_ids2017.parquet", out="configs/cic2017_controllability.csv"):
    cols = [c for c in pq.read_schema(parquet).names if c not in ("label", "attack_cat")]
    rows = [(c, *classify(c)) for c in cols]
    Path(out).parent.mkdir(exist_ok=True)
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["feature", "class_suggested", "rationale", "class_final", "notes"])
        for c, k, why in rows:
            w.writerow([c, k, why, "", ""])
    print(Counter(k for _, k, _ in rows))


if __name__ == "__main__":
    build()
