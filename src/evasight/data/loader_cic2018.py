"""CSE-CIC-IDS2018 loader: streaming CSV -> one Parquet, memory-safe on 8 GB RAM.

Per chunk: drop identifier columns, drop repeated header rows, coerce to numeric, drop
Inf/NaN rows, keep all attacks plus a seeded fraction of benign rows, drop exact duplicates
(global, via row hashes), append to Parquet. Audit -> data/interim/cic_ids2018_audit.json
"""
from __future__ import annotations

import json
from collections import Counter

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from ridsx.data.loaders import INTERIM, RAW, _snake

CHUNK = 100_000
DROP = {"Flow ID", "Src IP", "Src Port", "Dst IP", "Timestamp"}


def load_cic2018(benign_frac: float = 0.1, seed: int = 42) -> dict:
    rng = np.random.default_rng(seed)
    INTERIM.mkdir(parents=True, exist_ok=True)
    out = INTERIM / "cic_ids2018.parquet"
    audit, labels, seen = Counter(), Counter(), set()
    writer = schema = None
    for f in sorted((RAW / "cic_ids2018").glob("*.csv")):
        day = f.name.split("_")[0]
        reader = pd.read_csv(f, chunksize=CHUNK, dtype=str, encoding="latin-1",
                             usecols=lambda c: c.strip() not in DROP)
        for chunk in reader:
            audit["rows_read"] += len(chunk)
            chunk.columns = [c.strip() for c in chunk.columns]
            n0 = len(chunk)
            chunk = chunk[chunk["Label"] != "Label"]  # repeated header rows inside files
            audit["repeated_header_rows"] += n0 - len(chunk)
            lab = chunk.pop("Label").str.strip()
            feats = chunk.apply(pd.to_numeric, errors="coerce")
            feats.columns = [_snake(c) for c in feats.columns]
            ok = np.isfinite(feats.to_numpy("float64")).all(axis=1)
            audit["inf_nan_rows_removed"] += int((~ok).sum())
            feats, lab = feats[ok], lab[ok]
            benign = lab.str.lower().eq("benign").to_numpy()
            audit["benign_valid_rows"] += int(benign.sum())
            audit["attack_valid_rows"] += int((~benign).sum())
            keep = ~benign | (rng.random(len(lab)) < benign_frac)
            feats, lab, benign = feats[keep], lab[keep], benign[keep]
            if feats.empty:
                continue
            feats = feats.astype("float32")
            feats["attack_cat"] = np.where(benign, "BENIGN", lab.to_numpy())
            h = pd.util.hash_pandas_object(feats, index=False).to_numpy()
            fresh = ~pd.Series(h).duplicated().to_numpy()
            fresh &= np.fromiter((x not in seen for x in h), bool, len(h))
            seen.update(h[fresh].tolist())
            audit["duplicates_removed"] += int((~fresh).sum())
            feats = feats[fresh].reset_index(drop=True)
            feats["label"] = (feats["attack_cat"] != "BENIGN").astype("uint8")
            feats["source"] = day
            tbl = pa.Table.from_pandas(feats, preserve_index=False)
            if writer is None:
                schema = tbl.schema
                writer = pq.ParquetWriter(out, schema, compression="zstd")
            writer.write_table(tbl.cast(schema))
            labels.update(feats["attack_cat"].value_counts().to_dict())
            audit["rows_written"] += len(feats)
        print(f"done {f.name[:28]}  rows_written so far: {audit['rows_written']}", flush=True)
    writer.close()
    total = audit["benign_valid_rows"] + audit["attack_valid_rows"]
    res = {
        "dataset": "cic_ids2018", "benign_frac_kept": benign_frac, "seed": seed,
        **dict(audit), "label_counts": dict(labels.most_common()),
        "natural_attack_rate": audit["attack_valid_rows"] / total,
        "attack_rate_in_output": sum(v for k, v in labels.items() if k != "BENIGN")
        / audit["rows_written"],
    }
    (INTERIM / "cic_ids2018_audit.json").write_text(json.dumps(res, indent=2))
    return res


if __name__ == "__main__":
    print(json.dumps(load_cic2018(), indent=2))
