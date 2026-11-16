"""Model-agnostic grid-search evasion attack over the two realistic perturbation knobs."""
from __future__ import annotations

import itertools
from collections.abc import Callable

import numpy as np
import pandas as pd

from ridsx.attacks.perturb import perturb, recompute_derived
from ridsx.attacks.validity import rules

LEVELS = (0.0, 0.25, 0.5, 0.75, 1.0)


def grid_attack(flows: pd.DataFrame, score_fn: Callable[[pd.DataFrame], np.ndarray],
                eps: float, levels=LEVELS, threshold: float = 0.5):
    """Try every (pad, delay) combination and keep, per flow, the valid perturbation with the
    lowest attack score. flows: float64 attack flows with a default RangeIndex.
    score_fn: DataFrame -> attack probability per row (the target model).
    Returns (adversarial_flows, best_score, evaded). A perturbed flow counts only if it breaks
    no validity rule that the original flow satisfied; otherwise the original flow is kept.
    """
    ok0 = pd.DataFrame(rules(flows))
    best = np.asarray(score_fn(flows), dtype=float)
    adv = flows.copy()
    for a_pad, a_delay in itertools.product(levels, levels):
        cand = recompute_derived(flows, perturb(flows, a_pad, a_delay, eps))
        valid = ~(ok0 & ~pd.DataFrame(rules(cand))).any(axis=1).to_numpy()
        s = np.asarray(score_fn(cand), dtype=float)
        better = valid & (s < best)
        best = np.where(better, s, best)
        adv.loc[better] = cand.loc[better]
    return adv, best, best < threshold
