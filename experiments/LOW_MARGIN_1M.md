# Low-margin 1M no-refresh profile

Scope: b=3, k=5, T=5, sequential, no refresh. Optional profile:
`parameters/b3-k5/sequential-none-1M-low-margin.json`.
N=32768, t=1179649, Q=9×55≈495 bits, P≈61 bits, QP≈556 bits.
The previous Q540/P61 profile and campaign selections are unchanged.

The eight-prime Q480 candidate failed final-tally equality in all four synthetic
workloads (concentrated, balanced, random, carry), despite positive reported
residual margins. Small measured residuals alone do not establish correctness.
The Q495 candidate passed all four, with margins 12.918925, 11.307670,
14.046062 and 11.368580 bits respectively. A diagnostic minimum of zero was
explicitly used following user acceptance of low margins; the usual 20-bit
criterion is not met. No mathematical or final-tally constraint was relaxed.
A separate six-voter `go run .` fresh-input run also passed final verification.
These compact screens amplify residual noise for target n=1M; they are not
full-independent-input election simulations or worst-case correctness bounds.
No full-scale runtime benchmark was run.

Exact security estimates with estimator revision 53da5982597709ba0fdf94ea37a84d822310fd84
passed primal uSVP, dual-hybrid and classic dual: minimum 178.704 classical bits
under ADPS16 core-SVP, uniform ternary secret share, Gaussian sigma=3.2,
unlimited samples. This is separate from noise correctness and not a protocol proof.
The first estimator attempt failed because the earlier temporary checkout had
been cleaned up (ImportError); an approved fresh temporary checkout succeeded.

Nine Q limbs are still stored, so coefficient storage remains 4.5 MiB per
ciphertext. Smaller Q bit length does not imply smaller storage or faster runtime.

Run from the project root with the existing parameter-file override:

```bash
./experiments/scripts/run_n1M.sh --set b3-k5 --strategy sequential-none \
  --parameter-file experiments/parameters/b3-k5/sequential-none-1M-low-margin.json \
  --output-root experiments/results/low-margin-1M
```

Evidence and exact screen commands: `low-margin-1M-validation.json`.
Raw results and logs: `validation/low-margin-1M-20260922/`.
Created tracked candidates: this report, evidence JSON, and the parameter JSON.
Created local artifacts are enumerated in `validation/low-margin-1M-20260922/artifacts.txt`.
No production sources, current paper, or existing results were changed.
