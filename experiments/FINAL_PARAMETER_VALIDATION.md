# Concrete parameters for the current tally

2026-09-08. Lattigo v6.2.0; Go 1.26.1; b=k=5; T=5; qmax=1; three parties.

The files in [parameters/aligned-final/](parameters/aligned-final/) are concrete,
empirically screened parameter sets for the current shared-mask algorithm.
They are **not a proven analytical minimum**. Circuit depth and packing guided
the search; targeted encrypted checks supplied the correctness evidence.

## Files and generation settings

Every file has `Q mod t = t-1`. This makes the invariant multiplication scale
factor one. It avoids the extra scale matching caused by an arbitrary Q residue;
it does not eliminate encryption, multiplication, or key-switching noise.

| File stem | Assigned n | logN | Q prime bits × count | P prime bits × count | Minimum estimated classical bits |
| --- | --- | ---: | --- | --- | ---: |
| tree-none-t65537 | 200–50,000 | 15 | 48 × 8 | 61 × 1 | 241.192 |
| sequential-none-t65537 | 200–50,000 | 15 | 52 × 8 | 61 × 1 | 219.876 |
| tree-final-t65537 | 200–50,000 | 14 | 48 × 6 | 55 × 1 | 133.444 |
| sequential-final-t65537 | 200–50,000 | 14 | 48 × 6 | 55 × 1 | 133.444 |
| tree-none-t786433 | 100,000–500,000 | 15 | 55 × 8 | 61 × 1 | 205.860 |
| sequential-none-t786433 | 100,000–500,000 | 15 | 60 × 8 | 61 × 1 | 185.420 |
| tree-final-t786433 | 100,000–500,000 | 15 | 60 × 6 | 60 × 2 | 217.832 |
| sequential-final-t786433 | 100,000–500,000 | 15 | 60 × 6 | 60 × 2 | 217.832 |

Bit sizes in this table are approximate log2 values: generated primes lie below
the indicated powers of two. Exact decimal primes are in the JSON files.
Refreshed modes have separate names but identical numerical parameters within
each range. The parameters depend on n through two ranges; they were not minimized
separately for each of the nine voter counts.

To reproduce a file, use `scripts/generate_aligned_parameters.py` with its table
settings and a **new** output path. For example, from the project directory:

```bash
python3 experiments/scripts/generate_aligned_parameters.py \
  --name tree-none-t65537 --logN 15 \
  --q-prime-bits 48 --q-prime-count 8 \
  --p-bits 61 --p-prime-count 1 --plaintext-modulus 65537 \
  --output /tmp/tree-none-t65537.json
```

The generator uses distinct NTT primes and a final Q prime satisfying the residue
constraint. All eight resulting files were loaded and round-tripped through the
actual Lattigo parameter constructor, including the target voter-count bound.
The campaign generator now verifies these selected files instead of replacing
them with the old built-in profiles.

## Refresh and campaign scope

Refresh is after the completed echo, before the majority polynomial. It refreshes
both component totals (`2*C` ciphertexts). There are no intermediate refreshes.
The CLI uses `--refresh-mode=collective`, with interval 0 for tree and interval
T=5 for sequential. The latter suppresses all interior-period callbacks.

The 22-case runtime campaign is preserved: no-refresh tree and sequential at all
nine counts; tree-final and sequential-final only at 10k and 50k. The old
sequential-i2/i3 cases were replaced. Larger final-refresh files are available
without silently adding more runtime experiments.

## Correctness evidence and limitations

The validation covers all four families at each of
200, 500, 1,000, 5,000, 10,000, 25,000, 50,000, 100,000, and 500,000 target voters
with a randomized-workload synthetic screen. Additional balanced and
missing-submission carry screens cover the largest assigned target in each range.
Each trial generates fresh cryptographic randomness. Separate ordinary six-voter
runs exercise genuine input encryption for each of the four modes at t=65537.

The synthetic executable is a copied source tree produced by `prepare_screen.py`.
It executes the real echo and downstream tally with six probe voters. For each
period grid it encrypts a compact aggregate, then multiplies its residual error
by `min(target_n, voters_per_ciphertext)+1`. The extra one represents the zero
initializer. It also amplifies residuals at the cross-block reductions by the
target ciphertext count. The carry workload leaves periods 1 and 3 (zero-based)
without submissions to exercise echo explicitly.

These operations are a synthetic stress model, **not a proof of a worst-case
bound or a simulation of every independent voter encryption**. Compact plaintext
patterns do not exhaust every possible packed message. Full-electorate fresh-input
correctness and runtime experiments remain to be run on the experiment computer.

Passing requires all enabled plaintext checks, final threshold-decrypted tally
equality, and at least 20 bits at every recorded noise checkpoint, measured as
`log2(Q)-1-log2(t)-log2(maximum residual coefficient)`. The measured margin is
not a claimed whole-election failure probability. No deployment noise-flooding
requirement is included in the prototype refresh configuration.

All 62 checks using selected profiles passed (including preliminary checks),
with a minimum observed margin of 28.126 bits. All four ordinary six-voter
runs passed. The 36 all-count checks and 16 additional balanced/carry checks
are included in that total.

Exact successful screen counts and minima are in
[parameter-noise-screens.csv](parameter-noise-screens.csv). Source hashes,
commands, failed candidates, and fresh-input checks are recorded in
[parameter-validation.json](parameter-validation.json). Raw local logs remain
under the ignored `validation/final-refresh-20260908/` directory; they are not
runtime benchmark evidence.

Some rejected candidates are particularly informative:

- Q=240 bits with final refresh failed the 20-bit margin check.
- Q=288/P=55 at t=786433 also failed; increasing Q alone was insufficient.
  The selected large-count refresh set instead uses N=32768 and two P primes.
- Sequential/no-refresh Q=440 at target 500k failed with about 4.69 bits left;
  its selected Q is 480 bits.
- The initial Q=288 sequential/no-refresh 500k probe failed in the majority stage
  at about 13.23 bits. This probe preceded the carry-workload extension.

The failures were retained; they were not hidden by lowering the margin threshold
or changing the production mathematical relation.

## Lattice-security checks

[parameter-security.json](parameter-security.json) records fresh estimates for
each exact Q*P product. The six distinct numerical sets passed primal uSVP,
dual-hybrid, and classic dual checks under classical ADPS16 core-SVP costs,
uniform ternary unknown secret share, Gaussian error sigma 3.2, and unlimited
samples. The smallest estimate is 133.444 bits. These are model-dependent attack
estimates, not a security proof for the entire protocol.

The [lattice estimator](https://github.com/malb/lattice-estimator) checkout used
revision `53da5982597709ba0fdf94ea37a84d822310fd84`. The previously installed
checkout (`7ea215a4d55f200e06394399d8aa728c9092c5ef`) failed with an infinity/NaN
error in dual-hybrid estimation. A fresh temporary checkout succeeded. Sandbox
attempts also initially failed on Sage and Go cache access; the approved retries
succeeded. No project dependencies were upgraded.

## Validation commands

- `go test ./...` — passed after the cache-access retry.
- `python3 -m unittest discover -s experiments/scripts -p test_campaign.py` — six tests passed.
- `python3 experiments/scripts/generate_parameters.py --binary /private/tmp/voting-final-production` — all 22 campaign entries round-tripped.
- Additional Python checks verified all eight files' distinct primes, NTT and
  plaintext batching congruences, Q residues, and rejection of known composites.
- `sage experiments/scripts/estimate_parameters.py --estimator <temporary-checkout> --output <new-result.json> <six-distinct-parameter-files>` — all selected sets passed on the successful retry.
- The synthetic and ordinary fresh-input commands are retained in
  `parameter-validation.json`; no full-electorate runtime benchmark was run.

For repeat screening, prepare and build the copied source, then use
`screen_campaign.py --binary <screen-binary> --repeats 4`. It cycles through
concentrated, balanced, random, and carry workloads for the campaign families.
The final-refresh t786433 files are outside that runtime matrix; their explicit
commands are in the validation JSON.

## Files changed and artifacts

Source/scripts changed for this generation:

- `scripts/generate_aligned_parameters.py` (new).
- `scripts/generate_parameters.py`.
- `scripts/parameter_table.py`.
- `scripts/screen.go.txt`.
- `scripts/screen_campaign.py`.
- `scripts/test_campaign.py`.

Documentation changed: `../README.md`, `../EXPERIMENTS.md`,
`ANALYTICAL_PARAMETER_REVIEW.md`, and this new report. Existing user changes in
`main.go`, `helpers.go`, and `scripts/prepare_screen.py` were preserved; no
production Go source was edited for parameter generation.

Generated or regenerated committed-data candidates:

- The eight `parameters/aligned-final/*.json` files enumerated above.
- `experiments.csv` and `parameter-table.csv`.
- `parameter-security.json`, `parameter-noise-screens.csv`, and
  `parameter-validation.json`.

Local-only artifacts: candidate JSON files, screen/fresh logs, command records,
and raw metrics under `validation/final-refresh-20260908/`; copied screen source
under `/private/tmp/voting-campaign-screen-5l1sm2ql/`; executables
`/private/tmp/voting-final-refresh-screen` and `/private/tmp/voting-final-production`;
temporary orchestration scripts/case lists under `/private/tmp/`; and the estimator
checkout `/private/tmp/voting-estimator-final-20260908/`. Raw validation outputs
remain ignored by Git. No previous results were deleted or overwritten.

Final checks also passed: `git diff --check` and
`./experiments/scripts/run_n10000.sh --dry-run`, which emitted the expected four
strategies with final-only refresh flags and selected parameter paths.
