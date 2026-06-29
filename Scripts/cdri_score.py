#!/usr/bin/env python3
"""
cdri_score.py - Reproducible Composite DNS Resilience Index (CDRI) scoring.

This script reproduces the CDRI results reported in:
    "A Longitudinal Assessment of DNS Resilience and Robustness in Saudi Arabia"
    (Alharbi et al.), Section 3.1.3-3.1.6 and Table 8.

The CDRI is a *weighted additive* index over seven health-oriented dimensions,
each normalized to [0,1] with min-max normalization across domain categories:

    S1 = authoritative nameserver redundancy + topological (AS) diversity
    S2 = delegation correctness          (inverse of full+partial defective delegation)
    S3 = third-party provider independence (inverse of dependency)
    S4 = parent-child consistency        (inverse of PCI)
    S5 = Anycast adoption
    S6 = DNSSEC health                   (adoption + validation success)
    S7 = caching efficiency              (hit rate + TTL/latency)

    CDRI_c = sum_{i=1..7} w_i * S_{i,c}                                   (Eq. 10)

Default weights (sum to 1.0), as justified in Section 3.1.5:
    w1=0.20  w2=0.15  w3=0.10  w4=0.15  w5=0.10  w6=0.20  w7=0.10

Usage:
    # Reproduce the published ranking from the bundled aggregated data
    python3 Scripts/cdri_score.py --input Data/cdri_dimension_scores.csv

    # Run a Monte-Carlo weight-sensitivity analysis (Reviewer-requested robustness check)
    python3 Scripts/cdri_score.py --input Data/cdri_dimension_scores.csv \
            --sensitivity --trials 10000 --jitter 0.05

    # Score raw (un-normalized) metrics: normalize first, then aggregate
    python3 Scripts/cdri_score.py --input my_raw_metrics.csv --normalize \
            --risk-dimensions S2,S3,S4

The script depends only on the Python 3 standard library.
"""
import argparse
import csv
import statistics
from typing import Dict, List

# Dimension identifiers, in canonical order S1..S7.
DIMENSIONS = ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]

# Default CDRI weights (Section 3.1.5). Must sum to 1.0.
DEFAULT_WEIGHTS = {
    "S1": 0.20,  # NS redundancy / topological diversity
    "S2": 0.15,  # defective delegation (correctness)
    "S3": 0.10,  # third-party provider dependency
    "S4": 0.15,  # parent-child inconsistency (PCI)
    "S5": 0.10,  # Anycast adoption
    "S6": 0.20,  # DNSSEC adoption + validation
    "S7": 0.10,  # caching efficiency
}


def load_scores(path: str) -> List[Dict]:
    """Load category rows from a CSV with a 'category' column and S1..S7 columns.

    Comment lines starting with '#' are ignored so the data file can be
    self-documenting.
    """
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    reader = csv.DictReader(lines)
    for rec in reader:
        row = {"category": rec["category"].strip()}
        for dim in DIMENSIONS:
            row[dim] = float(rec[dim])
        rows.append(row)
    return rows


def minmax_normalize(rows: List[Dict], risk_dims: List[str]) -> List[Dict]:
    """Apply Eq. 9: min-max normalize each dimension across categories.

    For risk-oriented dimensions (higher = worse) the value is inverted first so
    that, after normalization, higher consistently means stronger resilience.
    """
    out = [dict(r) for r in rows]
    for dim in DIMENSIONS:
        vals = [r[dim] for r in rows]
        if dim in risk_dims:
            vals = [-v for v in vals]
        lo, hi = min(vals), max(vals)
        span = (hi - lo) or 1.0  # avoid divide-by-zero when a dimension is constant
        for r, v in zip(out, vals):
            r[dim] = (v - lo) / span
    return out


def compute_cdri(rows: List[Dict], weights: Dict[str, float]) -> List[Dict]:
    """Compute the weighted additive CDRI (Eq. 10) for each category."""
    scored = []
    for r in rows:
        cdri = sum(weights[d] * r[d] for d in DIMENSIONS)
        scored.append({"category": r["category"], "CDRI": cdri,
                       **{d: r[d] for d in DIMENSIONS}})
    scored.sort(key=lambda x: x["CDRI"], reverse=True)
    return scored


def print_ranking(scored: List[Dict]) -> None:
    print(f"{'Rank':<5}{'Category':<12}{'CDRI':>8}   " +
          "  ".join(f"{d:>6}" for d in DIMENSIONS))
    print("-" * 78)
    for i, r in enumerate(scored, 1):
        print(f"{i:<5}{r['category']:<12}{r['CDRI']:>8.3f}   " +
              "  ".join(f"{r[d]:>6.3f}" for d in DIMENSIONS))


def sensitivity_analysis(rows: List[Dict], trials: int, jitter: float,
                         seed_offset: int = 0) -> None:
    """Monte-Carlo robustness check on the weighting scheme.

    Each trial perturbs every weight by a deterministic, reproducible pseudo-random
    offset in [-jitter, +jitter], renormalizes the weights to sum to 1, recomputes
    the CDRI ranking, and records each category's rank. We report the baseline rank
    alongside the rank distribution so reviewers can see how stable the ordering is
    under alternative weight sets. A purely additive index with bounded jitter should
    keep the top and bottom of the ranking stable; mid-ranks may swap.

    Determinism note: Date.now()/os.urandom are intentionally avoided; we use a
    splitmix-style integer hash so results are byte-for-byte reproducible.
    """
    baseline = compute_cdri(rows, DEFAULT_WEIGHTS)
    base_rank = {r["category"]: i for i, r in enumerate(baseline, 1)}
    rank_samples = {r["category"]: [] for r in rows}

    def rand01(n: int) -> float:
        # SplitMix64-style deterministic hash -> uniform in [0,1).
        x = (n + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        x = x ^ (x >> 31)
        return (x & 0xFFFFFFFF) / 0x100000000

    for t in range(trials):
        w = {}
        for k, d in enumerate(DIMENSIONS):
            r = rand01((t + seed_offset) * 31 + k)
            offset = (r * 2.0 - 1.0) * jitter
            w[d] = max(0.0, DEFAULT_WEIGHTS[d] + offset)
        total = sum(w.values()) or 1.0
        w = {d: w[d] / total for d in DIMENSIONS}
        ranked = compute_cdri(rows, w)
        for i, rec in enumerate(ranked, 1):
            rank_samples[rec["category"]].append(i)

    print(f"\nWeight-sensitivity analysis: {trials} trials, "
          f"jitter +/-{jitter:.2f} (uniform, weights renormalized)\n")
    print(f"{'Category':<12}{'Base rank':>10}{'Mean rank':>11}"
          f"{'Best':>6}{'Worst':>7}{'Rank std':>10}")
    print("-" * 56)
    for cat in sorted(rank_samples, key=lambda c: base_rank[c]):
        s = rank_samples[cat]
        print(f"{cat:<12}{base_rank[cat]:>10}{statistics.mean(s):>11.2f}"
              f"{min(s):>6}{max(s):>7}{statistics.pstdev(s):>10.2f}")
    # Stability summary: fraction of trials whose top-3 / bottom-3 set is unchanged.
    print("\nInterpretation: a small rank std (and Best==Worst at the extremes) means "
          "the\nsector ordering is robust to the chosen weights.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True,
                    help="CSV with 'category' and S1..S7 columns.")
    ap.add_argument("--normalize", action="store_true",
                    help="Apply min-max normalization (Eq. 9) before scoring. "
                         "Use when the input holds raw metric values, not the "
                         "already-normalized S1..S7 of Table 8.")
    ap.add_argument("--risk-dimensions", default="",
                    help="Comma-separated dimensions that are risk-oriented "
                         "(higher=worse) and must be inverted before normalization, "
                         "e.g. S2,S3,S4. Only used with --normalize.")
    ap.add_argument("--sensitivity", action="store_true",
                    help="Run a Monte-Carlo weight-sensitivity analysis.")
    ap.add_argument("--trials", type=int, default=10000)
    ap.add_argument("--jitter", type=float, default=0.05,
                    help="Max absolute weight perturbation per dimension.")
    args = ap.parse_args()

    rows = load_scores(args.input)
    if args.normalize:
        risk = [d.strip() for d in args.risk_dimensions.split(",") if d.strip()]
        rows = minmax_normalize(rows, risk)

    scored = compute_cdri(rows, DEFAULT_WEIGHTS)
    print("Composite DNS Resilience Index (CDRI) - baseline weights")
    print(f"Weights: " + ", ".join(f"{d}={DEFAULT_WEIGHTS[d]}" for d in DIMENSIONS))
    print()
    print_ranking(scored)

    if args.sensitivity:
        sensitivity_analysis(rows, args.trials, args.jitter)


if __name__ == "__main__":
    main()
