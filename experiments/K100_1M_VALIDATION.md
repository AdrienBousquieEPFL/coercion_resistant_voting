# k=100, n=1M: reuse of k=5 profiles

Checked b=3, k=100, T=5, sequential mode, three parties. All eight compact
synthetic screens passed intermediate plaintext checks and final-tally equality.

| Mode | Existing parameter file (under parameters/) | N | Q bits | QP bits | Minimum margin | Classical security estimate |
|---|---|---:|---:|---:|---:|---:|
| No refresh | b3-k5/sequential-none-1M-low-margin.json | 32768 | 495 | 556 | 14.755592 | 178.704 |
| Final refresh | b3-k5/smaller-refresh/sequential-final-1M.json | 16384 | 312 | 342 | 24.825097 | 134.028 |

Both use t=1179649, sufficient for the target voter count. No new primes or
profile copies are needed. These conclusions concern the listed low-margin
no-refresh and smaller-ring refresh profiles, not the original Q540/Q420 files.

Each profile was tested with concentrated, balanced, random and missing-submission
carry workloads using 101 probe voters and synthetic residual amplification for
target n=1M. The diagnostic threshold was zero under the user's low-margin
policy; all final-tally checks remained enabled. No-refresh falls below the usual
20-bit criterion, while every refresh trial exceeds it. These are empirical
correctness checks, not worst-case bounds or full independent voter-encryption
simulations. No full-scale runtime benchmark or ordinary fresh-input run was
performed in this investigation. Full-scale runtime and memory remain unmeasured.

Security reuses the previously computed exact N and QP estimates with the same
uniform ternary secret-share, Gaussian sigma=3.2 and unlimited-sample assumptions:
classical ADPS16 core-SVP costs, primal uSVP, dual-hybrid and classic dual,
estimator revision 53da5982597709ba0fdf94ea37a84d822310fd84. Changing k and n
leaves these estimator inputs unchanged. This is not a whole-protocol proof.

The copied screen source manifest matched current Go/module files. Exact commands,
parameter/source/binary hashes, all trial outcomes, and security source references
are in `k100-1M-validation.json`. Raw logs and metrics are under
`validation/k100-1M-20260922/`. All eight runs exited successfully; no tests failed.
`git diff --check` passed. No production sources or dependency files changed.

The revised k=100 campaign now includes both sequential n=1M configurations,
reusing these exact parameter files. See `REVISED_PARAMETER_RUNS.md` for separate
remote launch commands. No full-scale experiment has been launched locally.

Created: this report, `k100-1M-validation.json`, and local raw artifacts enumerated
in `validation/k100-1M-20260922/artifacts.txt`. Existing profiles and results are unchanged.
