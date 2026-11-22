import numpy as np
import pandas as pd
import pytest

from evasight.attacks.perturb import MSS, perturb, recompute_derived

COLS = ["total_fwd_packets", "act_data_pkt_fwd", "total_backward_packets",
        "total_length_of_fwd_packets", "total_length_of_bwd_packets",
        "fwd_packet_length_min", "fwd_packet_length_mean", "fwd_packet_length_max",
        "bwd_packet_length_min", "bwd_packet_length_max",
        "fwd_iat_mean", "fwd_iat_min", "fwd_iat_max", "fwd_iat_total",
        "flow_duration", "average_packet_size", "subflow_fwd_bytes", "packet_length_mean",
        "flow_bytes_s", "flow_packets_s", "fwd_packets_s", "avg_fwd_segment_size",
        "max_packet_length", "min_packet_length"]


@pytest.fixture
def flows():
    #       n  k  nb   lf    lb   fmin fmean fmax bmin bmax  iat_m iat_min iat_max iat_tot dur   avg   sub  pm  fbs fps fpsx seg  maxp minp
    rows = [
        [5, 3, 4,  900, 1200,    0, 180,  300, 0, 500, 1000,  10, 3000, 4000, 10000, 2100 / 9, 100, 200, 0, 0, 0, 180, 500, 0],   # A: mixed
        [3, 0, 2,    0,    0,    0,   0,    0, 0,   0,  500, 100,  900, 1000,  3000,       0,   0,   0, 0, 0, 0,   0,   0, 0],   # B: no payload
        [2, 2, 2,  400,  100,  150, 200,  250, 0,  60, 2000, 2000, 2000, 2000,  9000, 500 / 4,   0,  90, 0, 0, 0, 200, 250, 0],   # C: all data
        [4, 4, 1, 5600,  100, 1300, 1400, 1450, 0,  60,  800,  50, 2000, 2400,  4000, 5700 / 5,  0, 900, 0, 0, 0, 1400, 1450, 0],   # D: near MSS
        [1, 1, 1,  100,   50,  100, 100,  100, 0,  50,    0,   0,    0,    0,  1000, 150 / 2,   0,  75, 0, 0, 0, 100, 100, 0],   # E: single pkt
    ]
    df = pd.DataFrame(rows, columns=COLS, dtype="float64")
    # Flow-level gaps reuse the forward gaps; all are far below the 5 s activity
    # timeout, so the delay caps never bind in these fixture tests.
    df["flow_iat_min"], df["flow_iat_max"] = df["fwd_iat_min"], df["fwd_iat_max"]
    return df


@pytest.mark.parametrize("eps", [0.1, 0.5, 1.0])
def test_padding_invariants(flows, eps):
    q = perturb(flows, 1.0, 0.0, eps)
    n, k = flows["total_fwd_packets"], flows["act_data_pkt_fwd"]
    # mean is always total / n
    assert np.allclose(q["fwd_packet_length_mean"] * n, q["total_length_of_fwd_packets"])
    # never pushes a flow past the MSS, never grows a max that was already over it
    assert not ((q["fwd_packet_length_max"] > MSS) & (flows["fwd_packet_length_max"] <= MSS)).any()
    assert (q["fwd_packet_length_max"] >= flows["fwd_packet_length_max"]).all()
    # flows without payload are untouched
    no = k == 0
    assert (q.loc[no, "total_length_of_fwd_packets"] == flows.loc[no, "total_length_of_fwd_packets"]).all()
    # the minimum grows only when every forward packet carries data
    assert ((q["fwd_packet_length_min"] != flows["fwd_packet_length_min"]) <= (k == n)).all()


def test_padding_value_and_cap(flows):
    q = perturb(flows, 1.0, 0.0, 0.5)
    assert q.loc[0, "total_length_of_fwd_packets"] == 900 + 150 * 3   # floor(0.5*900/3)=150 per data pkt
    assert q.loc[0, "fwd_packet_length_max"] == 450
    assert q.loc[3, "fwd_packet_length_max"] == MSS                    # D is capped at the MSS


@pytest.mark.parametrize("eps", [0.1, 0.5, 1.0])
def test_delay_invariants(flows, eps):
    q = perturb(flows, 0.0, 1.0, eps)
    n = flows["total_fwd_packets"]
    multi = n > 1
    assert np.allclose(q.loc[multi, "fwd_iat_total"], (n[multi] - 1) * q.loc[multi, "fwd_iat_mean"])
    assert (q.loc[~multi, "fwd_iat_mean"] == flows.loc[~multi, "fwd_iat_mean"]).all()   # one packet: no gaps
    assert (q["fwd_iat_min"] >= flows["fwd_iat_min"]).all()


def test_zero_budget_is_identity(flows):
    pd.testing.assert_frame_equal(perturb(flows, 1.0, 1.0, 0.0), flows)


def test_subflow_bytes_scales_and_zero_stays_zero(flows):
    p = perturb(flows, 1.0, 0.0, 0.5)
    r = recompute_derived(flows, p)
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
