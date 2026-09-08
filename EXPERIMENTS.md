# Tally experiment campaign

This document describes the current 22-configuration runtime campaign for the
Go/Lattigo tally. Its purpose is to compare server runtime, memory, and refresh
cost across election sizes and echo strategies. ZK proof generation and
verification are outside this campaign.

The executable configuration list is [experiments/experiments.csv](experiments/experiments.csv).
The [parameter table](experiments/parameter-table.csv) records each case's
parameter assignment, packing, ciphertext counts, estimated security, and
synthetic noise-screen results. These files contain the individual cases;
this document explains their scope and interpretation.

## Configurations

All cases use `b=k=5`, `T=5`, `qmax=1`, three multiparty participants, and
Lattigo v6.2.0. Candidate and delegation votes share one encrypted voter-period mask. Inputs are added directly.

| Voters `n` | Input execution | Strategies | Cases |
|---:|---|---|---:|
| 200 | Fresh, five periods | Tree/no-refresh; sequential/no-refresh | 2 |
| 500 | Fresh, five periods | Tree/no-refresh; sequential/no-refresh | 2 |
| 1,000 | Fresh, five periods | Tree/no-refresh; sequential/no-refresh | 2 |
| 5,000 | Fresh, five periods | Tree/no-refresh; sequential/no-refresh | 2 |
| 10,000 | Benchmark, one input period | Both no-refresh modes; sequential refresh intervals 2 and 3 | 4 |
| 25,000 | Benchmark, one input period | Tree/no-refresh; sequential/no-refresh | 2 |
| 50,000 | Benchmark, one input period | Both no-refresh modes; sequential refresh intervals 2 and 3 | 4 |
| 100,000 | Benchmark, one input period | Tree/no-refresh; sequential/no-refresh | 2 |
| 500,000 | Benchmark, one input period | Tree/no-refresh; sequential/no-refresh | 2 |
| **Total** | | | **22** |

There are nine tree/no-refresh cases, nine sequential/no-refresh cases, and
four sequential/collective comparisons. Tree with refresh, other `(b,k)` shapes,
and refresh intervals 1 and 4 are outside this campaign. The old 75-case
campaign and its validation reports are historical; its raw results are retained.

At `n>=10000`, the scripts use `benchmark --sample-voters=n`: the ingestion
measurement processes all voters for one period. The downstream echo and tally
still model all five periods, using one set of target-sized period accumulators
at a time. This is
not a one-period election. Benchmark mode reuses encrypted-zero input fixtures;
it measures server throughput and is not evidence about independent-encryption
noise at the full electorate size. Any five-period ingestion projection is
reported separately from observed time.

## Selected parameters

The files in [experiments/parameters/](experiments/parameters/) contain concrete
Q and P primes, the plaintext modulus, ring degree, and pinned Lattigo version.
They are generated through the Go parameter construction. A parameter identifier
is recorded with each run.

| Use | Cases | LogN | Approx. log2 Q | Approx. log2 P | Plaintext modulus `t` | Estimated classical security |
|---|---:|---:|---:|---:|---:|---:|
| Both no-refresh modes, `n<=50000` | 14 | 15 | 600 (10 primes) | 61 (1 prime) | 65,537 | 140.45 bits |
| Both no-refresh modes, `n>=100000` | 4 | 15 | 600 (10 primes) | 61 (1 prime) | 786,433 | 140.45 bits |
| Sequential refreshed comparisons | 4 | 14 | 312 (6 primes) | 40 (1 prime) | 65,537 | 128.48 bits |

The corresponding files are `tree-none-15-t65537.json`,
`tree-none-15-t786433.json`, and `refresh-14-t65537.json`.
The `tree-none-15` filename is historical: both tree and sequential no-refresh
now deliberately use these exact same parameters for a direct runtime comparison.
The mode is selected by the command-line flags, not the parameter filename.
`refresh-15-t65537.json` is retained as a screened comparison profile; the
current matrix does not select it.

The plaintext modulus is chosen from the declared bound `n*qmax`, rather than
the realized random weight sum, and must exceed that bound. The evaluator uses
scale-invariant BGV arithmetic, so operation depth alone is not a count of
consumed Q levels. Noise and the polynomial evaluator's structural requirements
both matter. These are screened candidate profiles, not demonstrated globally
minimal or runtime-optimal parameters.

Security estimates use the exact product `Q*P`, uniform ternary secret
(one remaining unknown share), error standard deviation 3.2, unlimited samples,
and the classical ADPS16 core-SVP cost model. The estimator revision is
`53da5982597709ba0fdf94ea37a84d822310fd84`. Results for the evaluated attacks are
in [security.json](experiments/validation/security.json) and
[security-refresh14.json](experiments/validation/security-refresh14.json).
These are lattice-attack estimates, not a complete protocol security proof.
The prototype refresh uses ordinary error noise; deployment noise-flooding
requirements remain unresolved and could change the parameter requirements.

## Validation status

Sequential/no-refresh parameter development and validation are recorded in
[REDESIGN_VALIDATION.md](experiments/REDESIGN_VALIDATION.md). The initial
concentrated synthetic screens at target sizes 50,000 and 500,000 passed with
the existing 600-bit-Q profile. A shorter nine-prime, approximately 540-bit-Q
candidate at target 500,000 failed the 20-bit margin requirement (16.60 bits).
The selected 600-bit chain is a conservative shared comparison profile, not a
claim of the smallest possible modulus.

The synthetic screen runs the actual downstream computation with compact,
freshly encrypted payload/shared-mask aggregates and amplified residual error to
model packing and accumulation. It is a stress model, not an independent fresh
encryption for every target electorate submission. The diagnostic checks
plaintext correctness and a 20-bit minimum margin at recorded checkpoints:
`log2(Q) - log2(2*t) - log2(maximum residual error)`.

The parameter table records the new per-family trial counts, minimum margins,
and streaming-flow provenance. Each family is screened at its largest assigned
voter count; smaller configurations reuse that evidence. Fresh keys and
ciphertexts are generated each trial. Only workload seeds are reproducible.
These parameter screens and functional checks are not runtime measurements for
the full electorate. Larger fresh-input validation and full-scale peak memory
measurements remain outstanding.

The earlier period-streaming implementation checks remain documented in
[STREAMING_FLOW_VALIDATION.md](experiments/STREAMING_FLOW_VALIDATION.md). Their
75-case and width-100 references describe the historical campaign.

## Running the campaign

Copy the whole project, including `experiments/`, to the experiment computer.
Use Bash, Python 3, and Go **1.26.1**. On a new machine, fetch the pinned modules
once if they are not already cached:

```bash
cd coercion_resistant_voting
go mod download
./experiments/scripts/build.sh
```

The build script disables dependency downloads and requires Go 1.26.1 already
installed. If necessary, set `GO_BIN` to that executable's path. Sage and the
lattice estimator are not needed to run the runtime campaign.

Preview a slice, then execute it:

```bash
./experiments/scripts/run_n10000.sh --dry-run
./experiments/scripts/run_n10000.sh
```

`--dry-run` prints the selected commands without executing experiments or
creating results. Each `run_n*.sh` script selects all configurations for its
voter count and uses the parameter files from the matrix.

To execute the complete campaign sequentially, stopping on the first failure:

```bash
for n in 200 500 1000 5000 10000 25000 50000 100000 500000; do
  ./experiments/scripts/run_n${n}.sh || break
done
```

Defaults are one warm-up and three measured executions per configuration,
each in a fresh process: 88 process executions for the complete campaign.
Warm-ups are excluded from summaries. Workload seeds match across strategies
for the same dimensions and repetition; encryption randomness does not.
The runtime scripts use `--diagnostic-checks=final`, without noise diagnostics,
and a one-second metrics sampler.

Useful options, forwarded by every launcher:

```bash
# Restrict a slice and change measured repetition count:
./experiments/scripts/run_n10000.sh --shape 5,5 --strategy sequential-i2 --repeats 5

# Preview the new largest sequential/no-refresh case:
./experiments/scripts/run_n500000.sh --strategy sequential-none --dry-run

# Apply an optional 30-minute cap per process:
./experiments/scripts/run_n10000.sh --timeout 1800
```

Strategy names are `tree-none`, `sequential-none`, `sequential-i2`, and
`sequential-i3`. Shape and strategy filters may be repeated. The runtime timeout
default is **0 (no limit)**; there is no automatic 25-minute prediction gate.
Failures, missing final correctness results, or timeouts stop that invocation
and preserve its logs. Restarting a launcher creates a new campaign rather than
resuming the old one.

## Results and interpretation

Each invocation creates a unique directory under `experiments/results/` with:

- `campaign.json`: configurations, binary hash, and repetition settings;
- `executions.csv`: per-process status, elapsed time, seed, and result location;
- `logs/` and `raw/`: separate warm-up and measured execution evidence;
- `measurements-summary.csv`: medians, minima, maxima, and sample counts for
  successful measured executions, generated after a successful campaign.

New runs record `tally_flow=period-streaming-shared-mask-v2`. Phases 4.1 and
4.2 alternate across periods, and final refresh contributes another 4.2 row.
The summary sums repeated phase timings within each run before computing
statistics across measured runs. The existing phase instrumentation forces GC
at boundaries; the increased number of boundaries can affect total runtime.
Do not pool timings from the old batch flow with the new streaming flow.

Raw runs include metadata, phase/component timings, operation counts, object
sizes, sampled resource use, and `summary.json`. The summary script can also be
invoked on an interrupted campaign to summarize only its successful measured
runs:

```bash
python3 experiments/scripts/summarize.py experiments/results/<campaign-directory>
```

Use `server_observed_wall_ms:<scope>` for accumulator initialization plus
server aggregation and downstream phases with multiparty time
removed. Use `tally_observed_wall_ms:<scope>` for the same computation **including
all refresh calls**, and `tally_refresh_wall_ms` for refresh alone. Here scope is
`one_input_period` or `five_input_periods`; benchmark initialization and downstream
work still cover all five periods. Five-period projections are separately named
`server_projected_wall_ms:five_input_periods` and
`tally_projected_wall_ms:five_input_periods`.

`components.csv` records local multiparty protocols separately (including their
coordinator work); collective key generation and final threshold decryption
are outside both tally metrics. `phases.csv` records the overlapping multiparty
wall/CPU time within each phase so the summary can subtract it. Diagnostic
threshold decryptions have their own component. Other diagnostic overhead can
remain, so timing runs must use final-only diagnostics with noise checks off.
Older runs without the new timing columns retain only explicitly named legacy
inclusive estimates. Client input preparation is excluded from both new tally
metrics. Do not describe projected ingestion time as
measured full-election time, or benchmark fixture checks as full-scale noise
validation. Parameter changes are part of the strategy comparison: these runs
do not isolate the echo algorithm at identical cryptographic parameters.

Use process-wide OS peak RSS from `summary.json` for the headline memory value.
One-second samples provide approximate phase attribution. Do not add all rows
of `objects.csv` to estimate peak memory: different rows can describe the same
objects at different stages. Serialized ciphertext/message sizes describe
storage or communication payload; they are not process memory measurements or
measured network throughput.

## Packing and the 300 GB machine

With `w=max(b,k)` and `R=2^LogN`, the two-row packing gives:

```text
V = 2 * floor((R/2)/w)    voters per ciphertext
C = ceil(n/V)            ciphertext blocks per grid period
```

The table generator records these values. The active period has three packed
accumulators: candidate inputs, delegation inputs, and a shared mask. Together
they contain `3*C` ciphertexts. A fresh set is initialized for each period,
so `3*T*C` ciphertexts are created over
the full run, but they are not all retained simultaneously.

At period close, sequential echo updates its current effective choices and
running totals. Tree echo keeps completed affine segments `(a,b,c,d)` and
merges a segment as soon as its final period arrives, preserving the old
midpoint split. It retains O(log T) segments, each with up to `4*C` ciphertext
components per candidate/delegation channel (leaf components share pointers).
There are still `T-1` tree merges per channel/block and no repeated prefix-tally
calculation. Final refresh and sequential intermediate-refresh boundaries are
unchanged. Input additions remain sequential.

For `n=500000`, `b=k=5`, and the selected no-refresh profile, `V=6552` and
`C=77`. The active period's three accumulators contain 231 degree-one
ciphertexts: approximately **1.21 GB (1.13 GiB) of polynomial coefficients**.
The table separates active period accumulators from total allocations across
periods. This is not peak process memory: echo state, evaluation keys, encrypted
weights, temporaries, and garbage collection require more memory. In particular,
the later weight phase precomputes 6,552 full-level target-mask plaintexts for
this layout (approximately 17.2 GB of coefficients).

The target machine has 300 GB RAM. No 500,000-voter peak RSS has been measured
for the redesigned campaign. Run launchers one at a time and keep Go runtime
settings consistent and recorded when comparing modes. The scripts do not set
a memory cap. The historical width-100 memory estimates do not describe this
`b=k=5` campaign.

## Further work outside this campaign

Remaining work includes repeated and larger fresh-input noise validation,
measured memory feasibility, deployment refresh-noise analysis, and complete
serialized communication accounting. Packing-boundary experiments and broader
parameter searches may help choose faster or smaller profiles later. They are
not additional configurations silently included in the current 22-case matrix.

## Shared-mask protocol revision

Current runs use `tally_flow=period-streaming-shared-mask-v2`. Each submission
adds two payload ciphertexts and one shared mask; each period retains three
aggregate grids. Commitments remain outside the implementation. The parameter
files are unchanged. Existing results, validation reports, and the checked-in
parameter table are historical and do not establish performance or noise
margins for this revised flow. The table generator and synthetic screen use the
new flow; older screen evidence is labeled historical when generating tables.
