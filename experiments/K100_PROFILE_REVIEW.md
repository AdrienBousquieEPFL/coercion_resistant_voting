# k=100 parameter review (2026-09-22)

Scope: b=3, k=100, T=5, sequential, three parties. Defaults, paper tables and
historical results are unchanged. This is an empirical screen, not minimization.

## Sharing k=5 parameters through 50k

The current k=5 and k=100 refresh profiles are numerically identical:
N16384/Q288/P55/t65537. Four new synthetic workloads at target 50k all verified
the tally, with minimum margin 41.590989 bits.

The k=5 no-refresh profile N32768/Q416/P61/t65537 is NOT a validated replacement
for the full k=100 range. At target 50k, concentrated, random and carry workloads
failed final-tally equality; balanced passed. Recorded minimum margins were
0.247235, 0.245442, 0.126046 and 0.307719 bits respectively. These examples show
that a small positive diagnostic margin does not guarantee the intended plaintext.
Smaller target counts were not screened separately, so no conclusion is claimed
about exactly which lower counts could use this profile. Retain existing profiles.

## Smaller refresh profile at 100k and 500k

Optional file: `parameters/b3-k100/sequential-final-100k-500k-smaller-ring.json`.
It is an exact copy of the tested k=5 smaller-ring profile, preserving its identity:
N16384, Q=6×52≈312 bits, P=1×30≈30 bits, QP≈342 bits, t786433.
Compared with the current k=100 100k refresh profile N32768/Q360/P120,
this halves the ring degree and reduces ciphertext coefficient storage from
3 MiB to 1.5 MiB. Packing drops from 326 to 162 voters per ciphertext, so the
number of blocks grows from 307 to 618 at 100k and from 1534 to 3087 at 500k.
No additional refresh is needed by these checks; refresh remains final-only.
Runtime/memory improvement needs full-scale measurement.

All eight synthetic workloads passed final tally verification. Minimum margins:
34.694265 bits at 100k and 29.468162 bits at 500k. Four workloads per target:
concentrated, balanced, random and missing-submission carry. A zero diagnostic
threshold was used under the user's low-margin policy, but every refresh trial
also exceeded 20 bits. Production correctness checks were not weakened.

These screens use 101 probe voters with secret-assisted residual amplification
for target occupancy and cross-block reductions. They do not simulate every
independent encryption in a large election or prove a worst-case noise bound.
The screen source manifest was checked against the current Go/module files.

Exact N/QP security evidence is reused from the identical previously estimated
profile: minimum 134.028 classical bits for primal uSVP, dual-hybrid and classic
dual, with estimator 53da5982597709ba0fdf94ea37a84d822310fd84, ADPS16 core-SVP,
uniform ternary unknown secret share, Gaussian sigma=3.2, unlimited samples.
This is not a whole-protocol security proof or refresh-flooding analysis.

At 100k, benchmark with the existing launcher and parameter override:

```bash
./experiments/scripts/run_n100k.sh --set b3-k100 --strategy sequential-final \
  --parameter-file experiments/parameters/b3-k100/sequential-final-100k-500k-smaller-ring.json \
  --output-root experiments/results/smaller-refresh-k100
```

The k=100 campaign still stops at 100k; the 500k synthetic checks do not add a
500k configuration to the campaign. No full-scale benchmarks were run.

Created: this report, `k100-profile-review.json`, and the optional parameter JSON.
Raw logs/metrics, probe driver and complete artifact inventory are in
`validation/k100-profile-review-20260922/` (see `artifacts.txt`). Exact commands
and outcomes, including failures, are retained in the evidence JSON.

The ordinary 101-voter fresh-input run also passed intermediate/final tally
checks with a 20-bit threshold (minimum margin 54.780257 bits). Its exact
command and metadata are in the evidence JSON. Override dry-run and
`git diff --check` passed. No production sources changed; no unit tests rerun.
