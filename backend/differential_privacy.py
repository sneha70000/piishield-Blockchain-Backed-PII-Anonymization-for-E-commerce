"""
differential_privacy.py — Laplace-mechanism differential privacy for
aggregate analytics on anonymised datasets.

Directly implements the report's claim:
  "differential privacy techniques are incorporated to minimize the risk
   of re-identification... the anonymized data can then be safely used
   for analytics."

IMPORTANT SCOPE NOTE (say this in your viva, don't overclaim):
This applies differential privacy to AGGREGATE STATISTICS computed over
an anonymised dataset (counts, means, sums) — e.g. "how many customers
are in each city" — not to the raw anonymisation of individual PII
fields (that's handled by mask/hash/encrypt/tokenize, which is a
different, complementary privacy technique). This is the standard,
correct place to apply DP: at the point of releasing aggregate query
results, per the original Dwork et al. formulation.
"""

import numpy as np
import pandas as pd
from dataclasses import dataclass


@dataclass
class DPResult:
    true_value: float
    noisy_value: float
    epsilon: float
    mechanism: str


def _laplace_noise(sensitivity: float, epsilon: float) -> float:
    """
    Draws noise from the Laplace distribution scaled by sensitivity/epsilon.
    Smaller epsilon = more noise = stronger privacy, less accuracy.
    This is the classical Laplace mechanism (Dwork & Roth, 2014).
    """
    scale = sensitivity / epsilon
    return np.random.laplace(loc=0.0, scale=scale)


def dp_count(df: pd.DataFrame, epsilon: float = 1.0) -> DPResult:
    """Differentially private row count. Sensitivity = 1 (adding/removing
    one row changes the count by at most 1)."""
    true_count = len(df)
    noisy = true_count + _laplace_noise(sensitivity=1.0, epsilon=epsilon)
    return DPResult(true_value=true_count, noisy_value=max(0, round(noisy)), epsilon=epsilon, mechanism="laplace_count")


def dp_mean(series: pd.Series, epsilon: float = 1.0, value_range: tuple = None) -> DPResult:
    """
    Differentially private mean of a numeric column.
    Sensitivity is bounded by the value range (range/n) — caller should
    supply a reasonable (min, max) clip range for the column, since
    unbounded sensitivity would require infinite noise to guarantee privacy.
    """
    clean = series.dropna()
    n = len(clean)
    if n == 0:
        return DPResult(true_value=0.0, noisy_value=0.0, epsilon=epsilon, mechanism="laplace_mean")

    if value_range is None:
        value_range = (clean.min(), clean.max())
    lo, hi = value_range
    clipped = clean.clip(lower=lo, upper=hi)

    true_mean = float(clipped.mean())
    sensitivity = (hi - lo) / n if n > 0 else 1.0
    noisy = true_mean + _laplace_noise(sensitivity=sensitivity, epsilon=epsilon)
    return DPResult(true_value=true_mean, noisy_value=round(noisy, 2), epsilon=epsilon, mechanism="laplace_mean")


def dp_value_counts(series: pd.Series, epsilon: float = 1.0, top_n: int = 10) -> dict:
    """
    Differentially private category counts (e.g. "customers per city").
    Each category's count gets independent Laplace noise. This is the
    standard approach for private histograms/GROUP BY style aggregates.
    """
    true_counts = series.value_counts().head(top_n)
    result = {}
    for category, count in true_counts.items():
        noisy = count + _laplace_noise(sensitivity=1.0, epsilon=epsilon)
        result[str(category)] = {
            "true_count": int(count),
            "noisy_count": max(0, round(noisy)),
        }
    return result
