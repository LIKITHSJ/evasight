import numpy as np
import pandas as pd
import pytest

from evasight.attacks.perturb import MSS, perturb, recompute_derived

# (fwd packet lengths incl. empty SYN/ACK = 0, bwd lengths, iat_mean, iat_min, iat_max, duration, subflow_fwd_bytes)
RAW = [
    ([0, 0, 300, 300, 300], [0, 500, 350, 350], 1000, 10, 3000, 10000, 100),  # A mixed
    ([0, 0, 0], [0, 0], 500, 100, 900, 3000, 0),                              # B no payload
    ([250, 150], [0, 60], 2000, 2000, 2000, 9000, 0),                         # C all data
    ([1450, 1400, 1350, 1400], [60], 800, 50, 2000, 4000, 0),                 # D near MSS
    ([100], [50], 0, 0, 0, 1000, 0),                                          # E single packet
]


def _sd(x):
    return float(np.std(x, ddof=1)) if len(x) > 1 else 0.0


def _row(fwd, bwd, im, imin, imax, dur, sub):
    f, b = np.array(fwd, float), np.array(bwd, float)
    a = np.concatenate([f, b])
    n = len(f)
    return {
        "total_fwd_packets": n, "act_data_pkt_fwd": int((f > 0).sum()), "total_backward_packets": len(b),
        "total_length_of_fwd_packets": f.sum(), "total_length_of_bwd_packets": b.sum(),
        "fwd_packet_length_min": f.min(), "fwd_packet_length_mean": f.mean(),
        "fwd_packet_length_max": f.max(), "fwd_packet_length_std": _sd(f),
        "bwd_packet_length_min": b.min(), "bwd_packet_length_mean": b.mean(),
        "bwd_packet_length_max": b.max(), "bwd_packet_length_std": _sd(b),
        "fwd_iat_mean": im, "fwd_iat_min": imin, "fwd_iat_max": imax, "flow_iat_min": imin, "flow_iat_max": imax, "fwd_iat_total": im * (n - 1),
        "flow_duration": dur, "average_packet_size": a.mean(), "subflow_fwd_bytes": sub,
        "packet_length_mean": a.mean(), "packet_length_std": _sd(a), "packet_length_variance": _sd(a) ** 2,
        "flow_bytes_s": 0.0, "flow_packets_s": 0.0, "fwd_packets_s": 0.0, "avg_fwd_segment_size": f.mean(),
        "max_packet_length": a.max(), "min_packet_length": a.min(),
    }


@pytest.fixture
def flows():
    return pd.DataFrame([_row(*r) for r in RAW]).astype("float64")


@pytest.mark.parametrize("eps", [0.1, 0.5, 1.0])
def test_padding_invariants(flows, eps):
    q = perturb(flows, 1.0, 0.0, eps)
    n, k = flows["total_fwd_packets"], flows["act_data_pkt_fwd"]
    assert np.allclose(q["fwd_packet_length_mean"] * n, q["total_length_of_fwd_packets"])
    assert not ((q["fwd_packet_length_max"] > MSS) & (flows["fwd_packet_length_max"] <= MSS)).any()
    assert (q["fwd_packet_length_max"] >= flows["fwd_packet_length_max"]).all()
    no = k == 0
    assert (q.loc[no, "total_length_of_fwd_packets"] == flows.loc[no, "total_length_of_fwd_packets"]).all()
    assert ((q["fwd_packet_length_min"] != flows["fwd_packet_length_min"]) <= (k == n)).all()


def test_padding_value_and_cap(flows):
    q = perturb(flows, 1.0, 0.0, 0.5)
    assert q.loc[0, "total_length_of_fwd_packets"] == 900 + 150 * 3   # floor(0.5*900/3)=150 per data pkt
    assert q.loc[0, "fwd_packet_length_max"] == 450
    assert q.loc[3, "fwd_packet_length_max"] == MSS                    # D capped at the MSS


@pytest.mark.parametrize("eps", [0.1, 0.5, 1.0])
def test_padding_matches_direct_computation(flows, eps):
    """Pad the real packet lists, recompute every statistic directly, compare with the attack output."""
    q = recompute_derived(flows, perturb(flows, 1.0, 0.0, eps))
    for i, (fwd, bwd, *_) in enumerate(RAW):
        f, b = np.array(fwd, float), np.array(bwd, float)
        p = q.loc[i, "fwd_packet_length_max"] - f.max()
        f2 = np.where(f > 0, f + p, 0.0)
        a2 = np.concatenate([f2, b])
        want = {
            "total_length_of_fwd_packets": f2.sum(), "fwd_packet_length_mean": f2.mean(),
            "fwd_packet_length_std": _sd(f2), "fwd_packet_length_min": f2.min(),
            "fwd_packet_length_max": f2.max(), "average_packet_size": a2.mean(),
            "packet_length_mean": a2.mean(), "packet_length_std": _sd(a2),
            "packet_length_variance": _sd(a2) ** 2, "max_packet_length": a2.max(),
            "min_packet_length": a2.min(),
        }
        for col, v in want.items():
            assert q.loc[i, col] == pytest.approx(v, rel=1e-9, abs=1e-9), (i, col, eps)


@pytest.mark.parametrize("eps", [0.1, 0.5, 1.0])
def test_delay_invariants(flows, eps):
    q = perturb(flows, 0.0, 1.0, eps)
    n = flows["total_fwd_packets"]
    multi = n > 1
    assert np.allclose(q.loc[multi, "fwd_iat_total"], (n[multi] - 1) * q.loc[multi, "fwd_iat_mean"])
    assert (q.loc[~multi, "fwd_iat_mean"] == flows.loc[~multi, "fwd_iat_mean"]).all()
    assert (q["fwd_iat_min"] >= flows["fwd_iat_min"]).all()


def test_zero_budget_is_identity(flows):
    pd.testing.assert_frame_equal(perturb(flows, 1.0, 1.0, 0.0), flows)


def test_zero_budget_recompute_keeps_stats(flows):
    r = recompute_derived(flows, perturb(flows, 1.0, 0.0, 0.0))
    for c in ("packet_length_mean", "packet_length_std", "packet_length_variance", "average_packet_size"):
        assert np.allclose(r[c], flows[c], rtol=1e-9, atol=1e-9), c


def test_subflow_bytes_scales_and_zero_stays_zero(flows):
    r = recompute_derived(flows, perturb(flows, 1.0, 0.0, 0.5))
    assert r.loc[0, "subflow_fwd_bytes"] == pytest.approx(100 * 1350 / 900)
    assert (r.loc[flows["subflow_fwd_bytes"] == 0, "subflow_fwd_bytes"] == 0).all()



def test_delay_respects_cicflowmeter_timeouts():
    from evasight.attacks.perturb import ACTIVITY_TIMEOUT_US as A, FLOW_TIMEOUT_US as F
    # rows: normal, near activity timeout, mixed active/idle, all idle near flow timeout
    d = pd.DataFrame({
        "total_fwd_packets":           [5, 5, 5, 3],
        "act_data_pkt_fwd":            [0, 0, 0, 0],
        "total_length_of_fwd_packets": [0., 0, 0, 0],
        "fwd_packet_length_max":       [0., 0, 0, 0],
        "fwd_packet_length_min":       [0., 0, 0, 0],
        "fwd_packet_length_mean":      [0., 0, 0, 0],
        "fwd_packet_length_std":       [0., 0, 0, 0],
        "fwd_iat_mean":                [500., 1e6, 1e6, 6.5e6],
        "fwd_iat_min":                 [100., 10, 10, 6e6],
        "fwd_iat_max":                 [1000., A - 1000, 6e6, 7e6],
        "fwd_iat_total":               [2000., 4e6, 4e6, 13e6],
        "flow_iat_min":                [100., 10, 10, 6e6],
        "flow_iat_max":                [1000., A - 1000, 6e6, 7e6],
        "flow_duration":               [5000., 6e6, 2e7, F - 100_000],
    })
    t = (perturb(d, 0.0, 1.0, 1.0)["fwd_iat_max"] - d["fwd_iat_max"]).to_numpy()
    np.testing.assert_array_equal(t, [500, 1000, 0, 50_000])



def test_flows_with_forward_bulk_are_not_perturbed(flows):
    f = flows.assign(fwd_bytes_bulk_avg=[0.0, 0.0, 0.0, 500.0, 0.0])  # row D: bulk, padding would apply
    q = perturb(f, 1.0, 1.0, 1.0)
    pd.testing.assert_series_equal(q.iloc[3], f.iloc[3], check_names=False)
    assert (q.iloc[0] != f.iloc[0]).any()  # a non-bulk row still changes
