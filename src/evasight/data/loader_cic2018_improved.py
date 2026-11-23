"""Improved CSE-CIC-IDS2018 (Liu et al., CNS 2022): stream CSVs out of the zip -> Parquet + split metadata.

Same cleaning as the improved CIC-IDS2017 loader (identifier columns dropped, repeated headers and
non-finite rows removed, Label / Attempted Category consistency checked), plus a seeded benign sample
because the release has about 63M flows. No deduplication here; split.py does it.
Usage: python -m evasight.data.loader_cic2018_improved count | load [benign_frac]
"""
from __future__ import annotations

import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

ZIP = Path("data/raw/CSECICIDS2018_improved.zip")
INTERIM = Path("data/interim")
NAME = "cic_ids2018_improved"
CHUNK = 200_000
DROP = {"id", "Flow ID", "Src IP", "Src Port", "Dst IP"}


def snake(c: str) -> str:
    return re.sub(r"[^0-9a-z]+", "_", c.strip().lower()).strip("_")


def members(z: zipfile.ZipFile) -> list[str]:
    return sorted(m for m in z.namelist() if m.lower().endswith(".csv"))


def count() -> None:
    """Rows and labels per file, reading only the Label column."""
    total = Counter()
    with zipfile.ZipFile(ZIP) as z:
        for m in members(z):
            c = Counter()
            for ch in pd.read_csv(z.open(m), usecols=lambda x: x.strip() == "Label", dtype=str,
                                  chunksize=1_000_000, encoding="latin-1"):
                c.update(ch.iloc[:, 0].str.strip())
            c.pop("Label", None)
            print(f"{Path(m).name:34} rows {sum(c.values()):>11,}  benign {c.get('BENIGN', 0):>11,}", flush=True)
            total += c
    print(f"\nTOTAL rows {sum(total.values()):,} | benign {total.get('BENIGN', 0):,}")
    print(json.dumps(dict(total.most_common()), indent=1))


def load(benign_frac: float = 0.1, seed: int = 42) -> None:
    rng = np.random.default_rng(seed)
    INTERIM.mkdir(parents=True, exist_ok=True)
    a, labels = Counter(), Counter()
    w = mw = cols = None
    with zipfile.ZipFile(ZIP) as z:
        for m in members(z):
            day = Path(m).stem
            for ch in pd.read_csv(z.open(m), dtype=str, chunksize=CHUNK, encoding="latin-1"):
                ch.columns = [c.strip() for c in ch.columns]
                a["rows_read"] += len(ch)
                hdr = ch["Label"].str.strip().eq("Label")
                a["repeated_header_rows"] += int(hdr.sum())
                ch = ch[~hdr]
                lab = ch.pop("Label").str.strip()
                att = pd.to_numeric(ch.pop("Attempted Category"), errors="coerce")
                if (att.isna() | (lab.str.endswith(" - Attempted") != att.ne(-1))).any():
                    raise RuntimeError(f"Label / Attempted Category mismatch in {m}")
                ts = pd.to_datetime(ch.pop("Timestamp").str.strip(), errors="coerce")
                feat = [c for c in ch.columns if c not in DROP]
                if cols is None:
                    cols = feat
                elif feat != cols:
                    raise RuntimeError(f"Columns differ in {m}")
                X = ch[feat].apply(pd.to_numeric, errors="coerce")
                ok = np.isfinite(X.to_numpy("float64")).all(axis=1)
                a["nonfinite_rows_removed"] += int((~ok).sum())
                benign = lab.eq("BENIGN").to_numpy()
                a["benign_valid_rows"] += int((ok & benign).sum())
                a["other_valid_rows"] += int((ok & ~benign).sum())
                keep = ok & (~benign | (rng.random(len(lab)) < benign_frac))
                if not keep.any():
                    continue
                out = X[keep].astype("float32").reset_index(drop=True)
                out.columns = [snake(c) for c in out.columns]
                k_lab = lab[keep].reset_index(drop=True)
                attempted = k_lab.str.endswith(" - Attempted")
                out["attack_cat"] = k_lab
                out["attempted_category"] = att[keep].astype("int64").to_numpy()
                out["label"] = (~(k_lab.eq("BENIGN") | attempted)).astype("int8")
                out["source"] = day
                k_ts = ts[keep].reset_index(drop=True)
                a["ts_unparsed"] += int(k_ts.isna().sum())
                t = pa.Table.from_pandas(out, preserve_index=False)
                mt = pa.table({"source": pa.array([day] * len(out)), "ts": pa.array(k_ts)})
                if w is None:
                    w = pq.ParquetWriter(INTERIM / f"{NAME}.parquet", t.schema, compression="zstd")
                    mw = pq.ParquetWriter(INTERIM / f"{NAME}_splitmeta.parquet", mt.schema, compression="zstd")
                w.write_table(t.cast(w.schema))
                mw.write_table(mt)
                labels.update(k_lab.tolist())
                a["rows_written"] += len(out)
            print(f"done {day:28} rows_written so far {a['rows_written']:,}", flush=True)
    w.close()
    mw.close()
    valid = a["benign_valid_rows"] + a["other_valid_rows"]
    audit = {"dataset": "CSE-CIC-IDS2018 improved (Liu et al., CNS 2022)", "benign_frac_kept": benign_frac,
             "seed": seed, **dict(a), "label_counts": dict(labels.most_common()),
             "natural_non_benign_rate": a["other_valid_rows"] / valid,
             "excluded_identifier_columns": sorted(DROP)}
    (INTERIM / f"{NAME}_audit.json").write_text(json.dumps(audit, indent=2))
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    if sys.argv[1:2] == ["count"]:
        count()
    else:
        load(float(sys.argv[2]) if len(sys.argv) > 2 else 0.1)
