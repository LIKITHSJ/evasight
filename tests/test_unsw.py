import numpy as np
import pandas as pd
import pytest

from evasight.attacks.unsw import FLOW_TIMEOUT_S, perturb_unsw, rules_unsw

TCP = np.array([True, False, True])


@pytest.fixture
def flows():
    # rows: TCP with handshake, short UDP, TCP 0.1 s below the flow timeout (3 packets, no payload)
    return pd.DataFrame({
        "spkts": [10., 2, 3], "dpkts": [8., 2, 0], "sbytes": [1000., 200, 180], "dbytes": [800., 200, 0],
        "smean": [100., 100, 60], "dur": [1.0, 0.5, 59.9], "sinpkt": [1000 / 9, 500., 29950.],
        "rate": [17., 6., 2 / 59.9], "sload": [7200., 1600., 180 * 8 * 2 / 3 / 59.9], "dload": [5600., 1600., 0.],
        "synack": [0.01, 0., 0.], "ackdat": [0.02, 0., 0.], "tcprtt": [0.03, 0., 0.],
    })


def test_zero_budget_is_identity(flows):
    pd.testing.assert_frame_equal(perturb_unsw(flows, 1.0, 1.0, 0.0, TCP), flows)


def test_padding_payload_packets_only(flows):
    q = perturb_unsw(flows, 1.0, 0.0, 0.5, TCP)  # p = 0.5 * smean
    np.testing.assert_array_equal(q.sbytes, [1000 + 50 * 7, 200 + 50 * 2, 180])  # TCP: spkts - 3 carry payload
    np.testing.assert_array_equal(q.smean, [135., 150., 60.])
    np.testing.assert_allclose(q.sload, flows.sload * q.sbytes / flows.sbytes)
    pd.testing.assert_series_equal(q.dur, flows.dur)


def test_delay_scales_rates_and_respects_timeout(flows):
    q = perturb_unsw(flows, 0.0, 1.0, 1.0, TCP)
    t = (q.sinpkt - flows.sinpkt).to_numpy() / 1000
    np.testing.assert_allclose(q.dur, flows.dur + t * (flows.spkts - 1))
    assert (q.dur <= FLOW_TIMEOUT_S + 1e-9).all() and q.dur[2] == pytest.approx(FLOW_TIMEOUT_S)
    np.testing.assert_allclose(q.rate, flows.rate * flows.dur / q.dur)
    np.testing.assert_allclose(q.ackdat - flows.ackdat, [t[0], 0, 0])  # handshake only where seen
    pd.testing.assert_series_equal(q.synack, flows.synack)


def test_rules_hold_after_attack(flows):
    ok0 = pd.DataFrame(rules_unsw(flows))
    assert ok0.all().all()
    for a in (0.25, 1.0):
        ok = pd.DataFrame(rules_unsw(perturb_unsw(flows, a, a, 1.0, TCP)))
        assert not (ok0 & ~ok).any().any()
