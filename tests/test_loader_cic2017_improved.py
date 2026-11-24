import json

import pandas as pd
import pytest

from evasight.data import loader_cic2017_improved as loader


FILES = ("friday", "monday", "thursday", "tuesday", "wednesday")


def _configure_paths(monkeypatch, tmp_path):
    raw = tmp_path / "raw"
    interim = tmp_path / "interim"
    raw.mkdir()
    interim.mkdir()
    monkeypatch.setattr(loader, "RAW", raw)
    monkeypatch.setattr(loader, "INTERIM", interim)
    monkeypatch.setattr(loader, "OUTPUT", interim / "cleaned.parquet")
    monkeypatch.setattr(loader, "SPLITMETA", interim / "splitmeta.parquet")
    monkeypatch.setattr(loader, "AUDIT", interim / "audit.json")
    monkeypatch.setattr(loader, "CHUNK_SIZE", 2)
    return raw, interim


def _write_csv(path, rows):
    pd.DataFrame(
        rows,
        columns=["Label", "Attempted Category", "Timestamp", "Flow Bytes/s"],
    ).to_csv(path, index=False)


def test_timestamp_metadata_aligns_with_cleaned_rows(monkeypatch, tmp_path):
    raw, interim = _configure_paths(monkeypatch, tmp_path)
    expected = []
    for day_index, day in enumerate(FILES):
        rows = []
        for row_index in range(2):
            timestamp = f"2017-07-{day_index + 1:02d} 01:02:{row_index:02d}.123456"
            label = "BENIGN" if row_index == 0 else "DoS Hulk"
            feature = day_index * 10 + row_index
            rows.append((label, -1, timestamp, feature))
            expected.append((day, timestamp, feature, label))
        if day == "friday":
            # This row remains excluded by the pre-existing nonnumeric-feature policy.
            rows.append(("BENIGN", -1, "not-a-timestamp", "not-a-number"))
        _write_csv(raw / f"{day}.csv", rows)

    loader.main()

    cleaned = pd.read_parquet(interim / "cleaned.parquet")
    metadata = pd.read_parquet(interim / "splitmeta.parquet")
    audit = json.loads((interim / "audit.json").read_text(encoding="utf-8"))

    assert metadata.columns.tolist() == ["source", "ts"]
    assert len(metadata) == len(cleaned) == len(expected)
    assert metadata["source"].tolist() == cleaned["source"].tolist()
    assert metadata["source"].tolist() == [row[0] for row in expected]
    assert cleaned["flow_bytes_s"].tolist() == [row[2] for row in expected]
    assert cleaned["attack_cat"].tolist() == [row[3] for row in expected]
    assert cleaned["label"].tolist() == [
        0 if row[3] == "BENIGN" else 1 for row in expected
    ]
    assert metadata["ts"].tolist() == [
        pd.Timestamp(row[1]) for row in expected
    ]
    assert metadata["ts"].dt.tz is None
    assert "timestamp" not in cleaned.columns
    assert audit["timestamp_parsing"] == {
        "format": "%Y-%m-%d %H:%M:%S.%f",
        "unparsed_timestamps": 1,
        "unparsed_timestamp_count_includes_invalid_rows": True,
    }


def test_retained_row_with_unparseable_timestamp_fails(monkeypatch, tmp_path):
    raw, interim = _configure_paths(monkeypatch, tmp_path)
    existing_outputs = {
        loader.OUTPUT: b"existing cleaned output",
        loader.SPLITMETA: b"existing split metadata",
    }
    for path, contents in existing_outputs.items():
        path.write_bytes(contents)
    loader.AUDIT.write_text("existing audit", encoding="utf-8")

    for day in FILES:
        timestamp = (
            "not-a-timestamp"
            if day == "wednesday"
            else "2017-07-01 01:02:03.123456"
        )
        _write_csv(
            raw / f"{day}.csv",
            [("BENIGN", -1, timestamp, 10)],
        )

    with pytest.raises(RuntimeError, match=r"wednesday\.csv.*not-a-timestamp"):
        loader.main()

    for path, contents in existing_outputs.items():
        assert path.read_bytes() == contents
    assert loader.AUDIT.read_text(encoding="utf-8") == "existing audit"
    assert not [
        path for path in interim.iterdir() if path.name.endswith(".tmp")
    ]


def test_metadata_promotion_failure_restores_existing_outputs(
    monkeypatch, tmp_path
):
    raw, interim = _configure_paths(monkeypatch, tmp_path)
    original_contents = {
        loader.OUTPUT: b"original cleaned parquet bytes",
        loader.SPLITMETA: b"original split metadata bytes",
        loader.AUDIT: b"original audit bytes",
    }
    for path, contents in original_contents.items():
        path.write_bytes(contents)

    for day in FILES:
        _write_csv(
            raw / f"{day}.csv",
            [("BENIGN", -1, "2017-07-01 01:02:03.123456", 10)],
        )

    real_replace = loader.os.replace
    promotion_failure_triggered = False

    def fail_splitmeta_promotion_once(source, destination):
        nonlocal promotion_failure_triggered
        source_path = tmp_path / source if isinstance(source, str) else source
        if (
            not promotion_failure_triggered
            and destination == loader.SPLITMETA
            and source_path.name.startswith(f".{loader.SPLITMETA.stem}.")
            and source_path.name.endswith(".tmp")
            and ".backup." not in source_path.name
        ):
            promotion_failure_triggered = True
            raise OSError("simulated split metadata promotion failure")
        return real_replace(source, destination)

    monkeypatch.setattr(loader.os, "replace", fail_splitmeta_promotion_once)

    with pytest.raises(OSError, match="simulated split metadata promotion failure"):
        loader.main()

    assert promotion_failure_triggered
    for path, contents in original_contents.items():
        assert path.read_bytes() == contents
    assert not [
        path for path in interim.iterdir() if path.name.endswith(".tmp")
    ]
