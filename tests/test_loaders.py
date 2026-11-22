import pandas as pd

from evasight.data.loaders import _clean_label, _snake


def test_snake_strips_spaces_and_symbols():
    assert _snake(" Flow Bytes/s") == "flow_bytes_s"
    assert _snake("Fwd Header Length.1") == "fwd_header_length_1"


def test_clean_label_normalises_garbled_dash():
    s = pd.Series(["BENIGN", "Web Attack \x96 Brute Force", "DoS Hulk"])
    out = _clean_label(s).tolist()
    assert out == ["BENIGN", "Web Attack - Brute Force", "DoS Hulk"]
