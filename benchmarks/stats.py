"""Small, dependency-free statistics for the benchmarks.

* :func:`wilson` -- Wilson score interval for a binomial proportion.
* :func:`mcnemar_exact` -- exact two-sided McNemar test on paired binary outcomes.
* :func:`cluster_bootstrap` -- percentile bootstrap that resamples *captures*
  (clusters), so correlated effects inside one capture are not treated as independent.
* :func:`sign_test` / :func:`wilcoxon_signed_rank` -- paired tests over clusters.
* :func:`clopper_pearson` -- exact binomial interval (used where k = n).
* :func:`provenance` -- which workflow run (or local commit) produced a result file.
"""

from __future__ import annotations

import math
import os
import random
import subprocess  # nosec B404 - fixed git invocation, no shell
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
    return float(f"{min(1.0, 2 * tail):.4g}")  # 4 significant digits: tiny p-values stay visible


def percentile(xs: Sequence[float], q: float) -> float:
    s = sorted(xs)
    if not s:
        return float("nan")
    i = (len(s) - 1) * q
    lo, hi = math.floor(i), math.ceil(i)
    return s[lo] + (s[hi] - s[lo]) * (i - lo)


BOOT_REPS = 10_000
BOOT_SEED = 7


def cluster_bootstrap(rows: Sequence, stat: Callable[[Sequence], float], reps: int = BOOT_REPS,
                      seed: int = BOOT_SEED) -> tuple[float, float]:
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


def sign_test(better: int, worse: int) -> float:
    """Exact two-sided sign test on paired outcomes (ties dropped); same as an exact McNemar test."""
    return mcnemar_exact(better, worse)


def wilcoxon_signed_rank(diffs: Sequence[float]) -> float:
    """Two-sided Wilcoxon signed-rank p-value (zeros dropped, mid-ranks for ties).

    Exact (enumerating the null distribution of the rank sum) for up to 25 non-zero
    differences, normal approximation with tie correction above that.
    """
    d = [x for x in diffs if abs(x) > 1e-12]
    n = len(d)
    if n == 0:
        return 1.0
    order = sorted(range(n), key=lambda i: abs(d[i]))
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(abs(d[order[j + 1]]) - abs(d[order[i]])) <= 1e-12:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    w_plus = sum(r for r, x in zip(ranks, d) if x > 0)
    total = n * (n + 1) / 2
    if n <= 25:
        doubled = [int(round(2 * r)) for r in ranks]  # mid-ranks are multiples of 0.5
        counts = {0: 1}
        for r in doubled:
            nxt: dict[int, int] = {}
            for s, c in counts.items():
                nxt[s] = nxt.get(s, 0) + c
                nxt[s + r] = nxt.get(s + r, 0) + c
            counts = nxt
        obs = int(round(2 * w_plus))
        centre = int(round(total))  # 2 * (total / 2)
        dev = abs(obs - centre)
        tail = sum(c for s, c in counts.items() if abs(s - centre) >= dev)
        return round(min(1.0, tail / 2 ** n), 6)
    mean = total / 2
    ties: dict[float, int] = {}
    for r in ranks:
        ties[r] = ties.get(r, 0) + 1
    var = n * (n + 1) * (2 * n + 1) / 24 - sum(t ** 3 - t for t in ties.values()) / 48
    z = (abs(w_plus - mean) - 0.5) / math.sqrt(var) if var > 0 else 0.0
    return round(min(1.0, math.erfc(z / math.sqrt(2))), 8)


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact (Clopper-Pearson) interval for k successes in n trials, by bisection on the binomial tail."""
    if n == 0:
        return (0.0, 1.0)

    def cdf(x: int, p: float) -> float:
        return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(x + 1))

    def solve(f: Callable[[float], float]) -> float:
        lo, hi = 0.0, 1.0
        for _ in range(100):
            mid = (lo + hi) / 2
            if f(mid) > 0:
                lo = mid
            else:
                hi = mid
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else solve(lambda p: alpha / 2 - (1 - cdf(k - 1, p)))
    upper = 1.0 if k == n else solve(lambda p: cdf(k, p) - alpha / 2)
    return (round(lower, 4), round(upper, 4))


def provenance(workflow: str) -> dict[str, str]:
    """Where a result file came from: the Actions run (GITHUB_RUN_ID, GITHUB_SHA) or ``local`` + git SHA."""
    run = os.environ.get("GITHUB_RUN_ID")
    repo = os.environ.get("GITHUB_REPOSITORY", "rakshit-737/revenant")
    if run:
        return {"workflow": os.environ.get("GITHUB_WORKFLOW", workflow), "run_id": run,
                "run_url": f"https://github.com/{repo}/actions/runs/{run}",
                "head_sha": os.environ.get("GITHUB_SHA", "")}
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,  # noqa: S603,S607
                             check=False, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        sha = ""
    return {"workflow": workflow, "run_id": "local", "run_url": "", "head_sha": sha}
