# Low-margin k=100 no-refresh profile

Scope: b=3, k=100, T=5, sequential echo, no refresh, three parties.
Candidate: `parameters/b3-k100/sequential-none-100k-500k-low-margin.json`.
N=32768, t=786433, Q=8×60≈480 bits, P=1×61≈61 bits, QP≈541 bits.
The old 100k profile has Q540/P120 (QP660). Active matrices are unchanged;
the k=100 runner still stops at 100k. No full-scale 500k experiment is configured.

All eight copied-source synthetic checks passed intermediate plaintext checks
and final-tally equality: concentrated, balanced, random and carry workloads
at each of target n=100k and n=500k, using 101 probe voters. Minimum margins:
12.271579 bits at 100k; 9.245895 bits at 500k. The diagnostic threshold was
explicitly set to zero following user acceptance of low margins. These results
do not meet the ordinary 20-bit screening criterion. No tally relation or
final equality check was relaxed.

Synthetic residual amplification is neither a full-independent-encryption
simulation nor a worst-case correctness/failure-probability bound.
No full-scale performance runs were executed. Runtime benefit remains unmeasured.
Ciphertext coefficient storage falls from 4.5 to 4 MiB. P shrinks too, but its
change affects key-switch decomposition and should not be assumed to improve
all operations proportionally.

Exact estimates passed primal uSVP, dual-hybrid and classic dual; minimum
185.42 classical bits with estimator revision 53da5982597709ba0fdf94ea37a84d822310fd84,
ADPS16 core-SVP costs, uniform ternary secret share, Gaussian sigma=3.2 and
unlimited samples. This is not a whole-protocol security proof.

Evidence, screen commands, exact security results and source hashes are in
`low-margin-k100-validation.json`. Raw logs/metrics and the probe driver are
under `validation/low-margin-k100-20260922/`. The copied screen sources matched
all current Go sources and module files before testing. No production code,
defaults, dependencies, existing results, or paper tables were changed.

To benchmark at 100k after copying the profile to the experiment machine:

```bash
./experiments/scripts/run_n100k.sh --set b3-k100 --strategy sequential-none \
  --parameter-file experiments/parameters/b3-k100/sequential-none-100k-500k-low-margin.json \
  --output-root experiments/results/low-margin-k100
```

Created: this report, evidence JSON and the optional parameter JSON. Complete
local artifact list: `validation/low-margin-k100-20260922/artifacts.txt`.

The ordinary 101-voter fresh-input check passed all enabled diagnostics and
final tally equality (minimum margin 37.185514 bits). Its exact command
is retained in the evidence JSON. The 100k launcher override dry-run and
`git diff --check` passed. No tests failed in this investigation.
