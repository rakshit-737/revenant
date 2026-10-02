"""Small, dependency-free statistics for the benchmarks.

* :func:`wilson` -- Wilson score interval for a binomial proportion.
* :func:`mcnemar_exact` -- exact two-sided McNemar test on paired binary outcomes.
* :func:`cluster_bootstrap` -- percentile bootstrap that resamples *captures*
  (clusters), so correlated effects inside one capture are not treated as independent.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes out of n."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (round(max(0.0, mid - half), 4), round(min(1.0, mid + half), 4))


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value; b, c are the discordant-pair counts."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return round(min(1.0, 2 * tail), 4)


def percentile(xs: Sequence[float], q: float) -> float:
    s = sorted(xs)
    if not s:
        return float("nan")
    i = (len(s) - 1) * q
    lo, hi = math.floor(i), math.ceil(i)
    return s[lo] + (s[hi] - s[lo]) * (i - lo)


def cluster_bootstrap(rows: Sequence, stat: Callable[[Sequence], float], reps: int = 2000,
                      seed: int = 7) -> tuple[float, float]:
    """95% percentile CI of ``stat`` over resampled clusters (rows)."""
    rng = random.Random(seed)
    n = len(rows)
    if n == 0:
        return (float("nan"), float("nan"))
    vals = []
    for _ in range(reps):
        sample = [rows[rng.randrange(n)] for _ in range(n)]
        v = stat(sample)
        if not math.isnan(v):
            vals.append(v)
    return (round(percentile(vals, 0.025), 4), round(percentile(vals, 0.975), 4))


def prf(tp: int, fp: int, hit: int, n: int) -> tuple[float, float, float]:
    """Precision, recall, F1 from edge counts (recall counts effects with a correct cause)."""
    p = tp / (tp + fp) if tp + fp else 0.0
    r = hit / n if n else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f
