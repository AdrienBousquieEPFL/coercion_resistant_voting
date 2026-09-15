# b=3 experiment parameter validation

Date: 2026-09-15. Lattigo v6.2.0; Go 1.26.1; T=5; qmax=1;
three parties; uniform ternary unknown secret share; Gaussian error sigma=3.2.

## Status and scope

The active matrices have 20 sequential configurations for k=5 through 1M and
32 tree/sequential configurations for k=100 through 100k. Each includes with
and without final refresh. Existing small-k profiles are retained by default.
**The original small-k no-refresh profiles failed the new synthetic margin
checks at 50k and 500k. They are not validated for the changed shape/flow.**
New stronger alternatives are available without overwriting any old parameters.
`generate_campaigns.py --strengthen-small-k` opts into those alternatives;
without that flag the generator preserves the requested existing parameters.
The new 1M profiles are selected regardless of that option.

All parameter choices are empirical baselines, not analytical minima. No
full-electorate runtime campaign was executed for this task. Full-scale memory
and runtime feasibility, especially for k=100, remain to be measured.

## Depth and efficiency

At T=5 the masked-input echo depth is 4 for tree and 5 for sequential.
The majority polynomial adds 3 ciphertext multiplication layers, encrypted
weighting adds 1, and the final weighted vote adds 1. Consequently, total depth
is 9 (tree) or 10 (sequential); final refresh divides it into segments of at most
5. Increasing k changes width, rotations, and noise accumulation, not this depth.
No extra refreshes are needed by the screened candidates. Tree uses final
refresh with interval 0; sequential uses interval T=5, with no intermediate
callbacks. No cryptographic constraint or tally relation was weakened.

At N=32768, k=100 packs 326 voters per ciphertext, requiring 307 blocks at
100k; k=50 would pack 654 and need 153 blocks. k=5 needs only 16 blocks.
Thus lowering k could roughly halve block-based costs and reduce delegation
key/mapping costs, but is not required to achieve the selected depth/noise
budgets. Keep k=100 as requested; this is not a claim of equal runtime to k=5.
The active-period accumulator storage formula alone (excluding keys, echo
state and downstream temporaries) is 3*C*2*N*len(Q)*8 bytes. For sequential
no-refresh k=100 at 100k that is about 4.05 GiB; actual process memory is higher.

## Concrete budgets and screens

Q/P values below are approximate bit totals; exact primes are decimal strings
in each JSON. Every file has full-batching prime t > n*qmax for its assigned
range, Q mod t = t-1, and distinct Q/P primes. The 1M plaintext modulus is
1,179,649, replacing 786,433 which is too small for that voter bound.

Screens use concentrated, balanced, random and missing-submission carry
patterns, fresh cryptographic randomness, and the existing copied-source
synthetic residual-amplification model. Acceptance requires all enabled plaintext
checks, final tally equality, and >=20 bits at recorded noise checkpoints.
Initial carry probes are also included when their exact parameter files match
those currently selected. Trial counts are correctness screens, not runtime
benchmark repetitions. The screen uses 6 probe voters for k=5 and 101 for k=100,
amplifying noise for the target packing occupancy and cross-block reductions.
This does not simulate all independent encryptions or establish a worst-case
noise/failure-probability bound. Prototype refresh flooding remains unresolved.

| Parameter file | logN | Q bits | P bits | t | Matching screen trials | Minimum margin | Status |
|---|---:|---:|---:|---:|---:|---:|---|
| `parameters/aligned-final/sequential-final-t65537.json` | 14 | 288 | 55 | 65537 | 5 | 48.36 | passed screens |
| `parameters/aligned-final/sequential-final-t786433.json` | 15 | 360 | 120 | 786433 | 5 | 80.53 | passed screens |
| `parameters/aligned-final/sequential-none-t65537.json` | 15 | 416 | 61 | 65537 | 1 | 1.60 | failed criterion |
| `parameters/aligned-final/sequential-none-t786433.json` | 15 | 480 | 61 | 786433 | 1 | 12.84 | failed criterion |
| `parameters/b3-k100/sequential-final-100k.json` | 15 | 360 | 120 | 786433 | 5 | 80.04 | passed screens |
| `parameters/b3-k100/sequential-final-50k.json` | 14 | 288 | 55 | 65537 | 5 | 43.98 | passed screens |
| `parameters/b3-k100/sequential-none-100k.json` | 15 | 540 | 120 | 786433 | 4 | 73.04 | passed screens |
| `parameters/b3-k100/sequential-none-50k.json` | 15 | 480 | 61 | 65537 | 4 | 62.97 | passed screens |
| `parameters/b3-k100/tree-final-100k.json` | 15 | 360 | 120 | 786433 | 5 | 80.45 | passed screens |
| `parameters/b3-k100/tree-final-50k.json` | 14 | 288 | 55 | 65537 | 5 | 43.44 | passed screens |
| `parameters/b3-k100/tree-none-100k.json` | 15 | 480 | 61 | 786433 | 5 | 48.58 | passed screens |
| `parameters/b3-k100/tree-none-50k.json` | 15 | 480 | 61 | 65537 | 4 | 92.85 | passed screens |
| `parameters/b3-k5/sequential-final-1M.json` | 15 | 420 | 120 | 1179649 | 5 | 131.48 | passed screens |
| `parameters/b3-k5/sequential-none-1M.json` | 15 | 540 | 61 | 1179649 | 5 | 59.37 | passed screens |
| `parameters/b3-k5/sequential-none-500k.json` | 15 | 540 | 61 | 786433 | 4 | 69.51 | passed screens |
| `parameters/b3-k5/sequential-none-50k.json` | 15 | 480 | 61 | 65537 | 4 | 62.49 | passed screens |

Rejected initial candidates and exact parameter snapshots are retained in
`parameter-search-b3.json`. Failed carry screens included k=100 tree/no-refresh
Q=384 (~0.21 bits), sequential/no-refresh Q=416 (~1.48 bits) and Q=480 at 100k
(~15.16 bits), plus the requested original k=5 sequential profiles (~1.60 and
12.84 bits). The replacement Q budgets are 480 at <=50k and 540 for the larger
sequential cases. No earlier parameter files or runtime results were rewritten.

For the 100k sequential/no-refresh profile, Q=540 uses two 60-bit P primes.
This increases the Q*P budget to about 660 bits but reduces the RNS key-switch
partition count compared with one P prime, reducing evaluation-key coefficient
storage. The Q540/P61 intermediate proposal was not screened; its snapshot is
retained locally. No controlled performance improvement is claimed from the
screen elapsed times.

## Security evidence and limitation

Fresh exact-modulus estimates completed on 2026-09-16 using the temporary,
user-authorized lattice-estimator checkout at revision
`53da5982597709ba0fdf94ea37a84d822310fd84` (2026-08-19). The installed revision
`7ea215a4d55f200e06394399d8aa728c9092c5ef` (2024-04-08) had failed with
`ValueError: Calling ceil() on infinity or NaN`. The temporary revision is newer,
and is the same revision used for the earlier successful parameter estimates.
Project dependencies and the installed estimator were not changed.

`parameter-security-b3.json` now records fresh estimates for all 16 profiles,
including both optional stronger k=5 profiles. Nine distinct `(logN, Q*P)` pairs
were evaluated; identical pairs share their result, with the representative file
and each parameter file hash recorded. All passed the 128-bit target. The minimum
is **133.444 bits**. The k=100 sequential/no-refresh 100k profile (Q540/P120)
has a minimum estimate of **140.744 bits**. No campaign parameter selection changed.

The evaluated attacks are primal uSVP, dual-hybrid, and classic dual, using
classical ADPS16 core-SVP costs, unlimited samples, a uniform ternary unknown
secret share, and Gaussian error sigma=3.2. These are model-dependent attack-cost
estimates, not a whole-protocol security proof or a correctness/noise bound.
Deployment refresh-noise flooding and missing protocol proofs remain outside scope.

The exact command is in `parameter-validation-b3.json`. Raw results and the earlier
reference-budget evidence are retained under `validation/b3-campaigns/` as
`security-exact-20260916.json` and `security-reference-before-exact-20260916.json`.
The first sandboxed attempt failed on Sage cache access; the approved retry
completed all estimates successfully. No FHE benchmarks were rerun.

## Production-input checks

Four small production-binary runs passed with fresh input encoding/encryption,
all plaintext diagnostics, the 20-bit noise criterion and final tally equality:
k=100 tree/no-refresh and sequential/final-refresh at n=101 (covering N=32768
and N=16384), plus both new 1M profiles at probe n=6. These are small correctness
checks with the new parameter files, not tests of one million independent voters.
Exact commands and source/binary hashes are in `parameter-validation-b3.json`.

All 56 four-pattern checks of the new/strengthened candidate families passed;
the smallest observed margin was 43.441792 bits. These checks include the optional
stronger small-k no-refresh profiles, rather than the two original profiles that
failed their initial carry checks. All included screen parameter identifiers were
checked against the current exact JSON files before collecting the evidence.

## Reproduction and checks

```bash
python3 experiments/scripts/generate_campaigns.py
# Optional, after choosing the stronger first-set parameters:
# python3 experiments/scripts/generate_campaigns.py --strengthen-small-k
./experiments/scripts/build.sh
python3 experiments/scripts/generate_parameters.py --binary bin/voting-experiments
python3 -m unittest discover -s experiments/scripts -p test_campaign.py
python3 experiments/scripts/prepare_screen.py
# Build the printed copied-source directory with the pinned Go toolchain.
python3 experiments/scripts/screen_campaign.py --binary <screen-binary> --repeats 4
```

The selected families are screened at their largest assigned target, not every
individual target n. The original failed first-set profiles remain failed until
the optional stronger files are selected. The existing screen runner stops each
failed family while retaining independent results.

- `gofmt -w instrumentation.go` and `go test ./...`: passed. The sandboxed first
  test attempt failed building testmain; the approved cache-access retry passed.
- Nine campaign tests passed, including set selection, compact counts, repetition
  defaults, run preservation, warm-up exclusion, and timeout recording.
- All 18 set/launcher dry runs passed; all 52 active matrix parameter entries
  round-tripped through the Go/Lattigo parameter constructor.
- The initial build script invocation rejected the default Go 1.25.1. Setting
  GO_BIN to the already-installed Go 1.26.1 executable built successfully.
- The initial copied-screen build also required approved access to the Go cache.
- Sage first failed on sandbox cache access; after approval it reached the
  independent infinity/NaN estimator failure described above.
- A pinned estimator checkout was downloaded temporarily with user approval;
  project dependencies were unchanged, no previous results were deleted, and no
  full-scale runtime benchmarks were run. Raw screen timing is not performance
  evidence and may include contention between local diagnostic processes.

## Files and artifacts

Repository file changes, including generated data and removed old launcher names
(pre-existing plot_results.py edits are preserved and excluded):
- `EXPERIMENTS.md`
- `README.md`
- `experiments/B3_PARAMETER_VALIDATION.md`
- `experiments/analytical-requirements-b3.csv`
- `experiments/experiments-b3-k100.csv`
- `experiments/experiments-b3-k5.csv`
- `experiments/experiments.csv`
- `experiments/parameter-noise-screens-b3.csv`
- `experiments/parameter-search-b3.json`
- `experiments/parameter-security-b3.json`
- `experiments/parameter-table.csv`
- `experiments/parameter-validation-b3.json`
- `experiments/parameters/b3-k100/sequential-final-100k.json`
- `experiments/parameters/b3-k100/sequential-final-50k.json`
- `experiments/parameters/b3-k100/sequential-none-100k.json`
- `experiments/parameters/b3-k100/sequential-none-50k.json`
- `experiments/parameters/b3-k100/tree-final-100k.json`
- `experiments/parameters/b3-k100/tree-final-50k.json`
- `experiments/parameters/b3-k100/tree-none-100k.json`
- `experiments/parameters/b3-k100/tree-none-50k.json`
- `experiments/parameters/b3-k5/sequential-final-1M.json`
- `experiments/parameters/b3-k5/sequential-none-1M.json`
- `experiments/parameters/b3-k5/sequential-none-500k.json`
- `experiments/parameters/b3-k5/sequential-none-50k.json`
- `experiments/scripts/analytical_requirements.py`
- `experiments/scripts/generate_campaigns.py`
- `experiments/scripts/generate_parameters.py`
- `experiments/scripts/parameter_table.py`
- `experiments/scripts/run_campaign.py`
- `experiments/scripts/run_n1000.sh`
- `experiments/scripts/run_n10000.sh`
- `experiments/scripts/run_n100000.sh`
- `experiments/scripts/run_n100k.sh`
- `experiments/scripts/run_n10k.sh`
- `experiments/scripts/run_n1M.sh`
- `experiments/scripts/run_n1k.sh`
- `experiments/scripts/run_n25000.sh`
- `experiments/scripts/run_n25k.sh`
- `experiments/scripts/run_n5000.sh`
- `experiments/scripts/run_n50000.sh`
- `experiments/scripts/run_n500000.sh`
- `experiments/scripts/run_n500k.sh`
- `experiments/scripts/run_n50k.sh`
- `experiments/scripts/run_n5k.sh`
- `experiments/scripts/screen_campaign.py`
- `experiments/scripts/test_campaign.py`
- `instrumentation.go`

Generated data: the three campaign matrices; 12 new exact parameter JSONs
under `parameters/b3-k5/` and `parameters/b3-k100/`; `analytical-requirements-b3.csv`,
`parameter-table.csv`, `parameter-noise-screens-b3.csv`, `parameter-security-b3.json`,
`parameter-search-b3.json`, `parameter-validation-b3.json`, and this report. The four small-k JSONs include two
optional no-refresh replacements as well as the two required 1M files.

Local-only artifacts are `bin/voting-experiments`, the copied source and screen
binary in `/private/tmp/voting-campaign-screen-feyqg4pu/`, and
`experiments/validation/b3-campaigns/` (probe scripts, candidate snapshots,
commands, raw diagnostic CSV/JSON, logs, and derived check records). The raw
outputs are enumerated in the noise CSV and search JSON; they are not campaign
runtime results. Existing Rabat data, historical parameter JSONs, and unrelated
plotting changes are preserved.

Complete generated-file inventory (excluding compiler/interpreter caches):
[artifacts.txt](validation/b3-campaigns/artifacts.txt).

## Security follow-up artifacts (2026-09-16)

Changed source: `scripts/parameter_table.py` (security column renamed to
`lattice_security_bits`; `security_method` identifies exact estimates).
Updated documents: `../EXPERIMENTS.md` and this report.
Regenerated data: `parameter-security-b3.json`, `parameter-validation-b3.json`,
and `parameter-table.csv`. Complete follow-up artifact paths, including local
logs, command records, the temporary checkout and runner, are listed in
[security-artifacts-20260916.txt](validation/b3-campaigns/security-artifacts-20260916.txt).

Follow-up validation:

- `sage experiments/scripts/estimate_parameters.py --estimator /private/tmp/voting-estimator-b3-20260916 --output experiments/validation/b3-campaigns/security-exact-20260916.json <nine representative files>`: passed; the full argument list is recorded in `parameter-validation-b3.json`.
- `python3 experiments/scripts/parameter_table.py --screens experiments/parameter-noise-screens-b3.csv`: regenerated 52 rows.
- `python3 -m unittest discover -s experiments/scripts -p test_campaign.py`: all nine tests passed.
- Python assertions verified all 16 hashes, exact Q*P values, ring degrees, three attack results per profile, the 128-bit threshold, all 52 table rows, and preservation of original k=5 selections.
- `git diff --check`: passed. No Go code changed; no FHE benchmark was run.
- Initial Git download failed sandbox DNS resolution; its approved retry succeeded. The first Sage run failed sandbox cache access, and its approved retry succeeded.
