#!/usr/bin/env python3
"""Report circuit requirements, not a noise-certified choice of Q or P.

Scope: current shared-mask flow, b=k=5, T=5, qmax=1. No FHE execution.
The four families describe parameter coverage; they do not change experiments.csv.
"""

import argparse
import csv
import sys


VOTER_COUNTS = (200, 500, 1000, 5000, 10000, 25000, 50000, 100000, 500000)


def tree_depth(periods):
    """Propagate multiplication depth through the midpoint echo composition."""
    if periods < 1:
        raise ValueError("periods must be positive")
    if periods == 1:
        return (0, 1, 0, 1)  # a=c=1-mask; b=d=input*mask
    la, lb, lc, ld = tree_depth((periods + 1) // 2)
    ra, rb, rc, rd = tree_depth(periods // 2)
    return (
        max(ra, la) + 1,
        max(max(ra, lb) + 1, rb),
        max(lc, max(rc, la) + 1),
        max(ld, rd, max(rc, lb) + 1),
    )


def requirements(n, log_n, mode, final_refresh):
    if n < 5 or log_n not in (14, 15) or mode not in ("tree", "sequential"):
        raise ValueError("requires n>=5, logN in {14,15}, and a supported echo mode")
    periods, width = 5, 5
    voters_per_ct = 2 * ((1 << (log_n - 1)) // width)
    blocks = (n + voters_per_ct - 1) // voters_per_ct
    echo_depth = tree_depth(periods)[3] if mode == "tree" else periods
    # The degree-five majority circuit adds three multiplication layers;
    # encrypted weight multiplication and the final weighted vote add two.
    downstream_depth = 5
    return {
        "family": f"{mode}-{'final-refresh' if final_refresh else 'none'}",
        "n": n,
        "b": width,
        "k": width,
        "T": periods,
        "candidate_logN": log_n,
        "voters_per_ciphertext": voters_per_ct,
        "ciphertext_blocks": blocks,
        "max_submissions_per_block_per_period": min(n, voters_per_ct),
        "fresh_input_additions_all_periods": 3 * n * periods,
        "benchmark_input_additions": 3 * n,
        "period_accumulator_encryptions": 3 * blocks * periods,
        "echo_ct_multiplications": (8 if mode == "tree" else 2) * blocks * (periods - 1) + 2 * blocks * periods,
        "echo_ct_additions": (8 if mode == "tree" else 4) * blocks * (periods - 1),
        "echo_multiplication_depth": echo_depth,
        "majority_polynomial_evaluations": 2 * blocks,
        "downstream_ct_multiplications_excluding_polynomial": 3 * blocks,
        "downstream_multiplication_depth": downstream_depth,
        "uninterrupted_depth": max(echo_depth, downstream_depth) if final_refresh else echo_depth + downstream_depth,
        "final_refresh_ciphertexts": 2 * blocks if final_refresh else 0,
        "intermediate_refresh_ciphertexts": 0,
        "cli_refresh_mode": "collective" if final_refresh else "none",
        "cli_refresh_interval": periods if final_refresh and mode == "sequential" else 0,
        "minimum_Q_prime_count_in_current_loader": 4,
        "Q_selection_status": "unresolved-noise-bounds-required",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, nargs="+", default=VOTER_COUNTS)
    parser.add_argument("--logN", type=int, nargs="+", choices=(14, 15), default=(14, 15))
    args = parser.parse_args()
    if any(n < 5 for n in args.n):
        parser.error("n must be at least k=5")
    rows = [requirements(n, log_n, mode, refresh)
            for n in args.n for log_n in args.logN
            for mode in ("tree", "sequential") for refresh in (False, True)]
    writer = csv.DictWriter(sys.stdout, fieldnames=rows[0], lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)


if __name__ == "__main__":
    main()
