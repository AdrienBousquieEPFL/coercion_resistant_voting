# Tally experiment campaign

This document describes the current 75-configuration runtime campaign for the
Go/Lattigo tally. Its purpose is to compare server runtime, memory, and refresh
cost across election sizes and echo strategies. ZK proof generation and
verification are outside this campaign.

The executable configuration list is [experiments/experiments.csv](experiments/experiments.csv).
The [parameter table](experiments/parameter-table.csv) records each case's
parameter assignment, packing, ciphertext counts, estimated security, and
synthetic noise-screen results. These files contain the individual cases;
this document explains their scope and interpretation.

## Configurations

All cases use `T=5`, `qmax=1`, three multiparty participants, Lattigo v6.2.0,
and the five `(b,k)` shapes `(5,5)`, `(20,20)`, `(100,100)`, `(100,5)`, `(5,100)`.
Candidate and delegation submissions have separate range masks and share a
voter-period validity bit.

| Voters `n` | Input execution | Strategies, each with all five shapes | Cases |
|---:|---|---|---:|
| 200 | Fresh, five periods | Tree without refresh | 5 |
| 500 | Fresh, five periods | Tree without refresh | 5 |
| 1,000 | Fresh, five periods | Tree without refresh | 5 |
| 5,000 | Fresh, five periods | Tree without refresh | 5 |
| 10,000 | Benchmark, one input period | Tree without refresh; tree with collective refresh; sequential with collective refresh at intervals 2 and 3 | 20 |
| 25,000 | Benchmark, one input period | Tree without refresh | 5 |
| 50,000 | Benchmark, one input period | Tree without refresh; tree with collective refresh; sequential with collective refresh at intervals 2 and 3 | 20 |
| 100,000 | Benchmark, one input period | Tree without refresh | 5 |
| 500,000 | Benchmark, one input period | Tree without refresh | 5 |
| **Total** | | | **75** |

There are 45 tree/no-refresh cases and 30 refreshed comparisons. Sequential
without refresh and intervals 1 and 4 are outside this campaign.

At `n>=10000`, the scripts use `benchmark --sample-voters=n`: the ingestion
measurement processes all voters for one period. The downstream echo and tally
still model all five periods and retain target-sized period grids. This is
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
| Tree/no-refresh, `n<=50000` | 35 | 15 | 600 (10 primes) | 61 (1 prime) | 65,537 | 140.45 bits |
| Tree/no-refresh, `n>=100000` | 10 | 15 | 600 (10 primes) | 61 (1 prime) | 786,433 | 140.45 bits |
| All refreshed comparisons | 30 | 14 | 312 (6 primes) | 40 (1 prime) | 65,537 | 128.48 bits |

The corresponding files are `tree-none-15-t65537.json`,
`tree-none-15-t786433.json`, and `refresh-14-t65537.json`.
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

The retained evidence contains 40 successful synthetic screening executions:
25 initial families (including the larger-ring refreshed comparison), followed
by 15 families using the selected smaller-ring refreshed profile. For the
current matrix, this amounts to **one trial for each of 25 selected
parameter/shape/strategy families**, screened at the largest assigned `n`.
It does not mean 40 trials for every case or full-scale fresh-input validation.

The synthetic screen runs the actual downstream computation with compact,
freshly encrypted validity-gated aggregates and amplified residual error to
model packing and accumulation. It is a stress model, not an independent
fresh encryption for each of the target electorate's submissions. The
concentrated-workload trials passed plaintext checks and a 20-bit minimum
checkpoint margin. The diagnostic estimates the margin as
`log2(Q) - log2(2*t) - log2(maximum residual error)` and checks pre-refresh
states as well as later checkpoints.

Recorded screens are under
[screen-e1zlx_nf](experiments/validation/screen-e1zlx_nf/) and
[screen-jeiukmsr](experiments/validation/screen-jeiukmsr/). The validation directory
also retains small fresh-input and benchmark smoke runs. Go tests and the Python
campaign tests have passed; these functional checks are not performance results.

Before treating the selected profiles as fully validated, run repeated noise
screens across concentrated, balanced, and random workloads (the screening
script defaults to 20 independent trials per family), and fresh-input checks
at feasible larger sizes. Encryption and keys are freshly random on each run;
only the simulated workload seed can be replayed. Full-scale runtime and peak
memory measurements on the target computer remain outstanding.

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
each in a fresh process: 300 process executions for the complete campaign.
Warm-ups are excluded from summaries. Workload seeds match across strategies
for the same dimensions and repetition; encryption randomness does not.
The runtime scripts use `--diagnostic-checks=final`, without noise diagnostics,
and a one-second metrics sampler.

Useful options, forwarded by every launcher:

```bash
# Restrict a slice and change measured repetition count:
./experiments/scripts/run_n10000.sh --shape 5,5 --strategy sequential-i2 --repeats 5

# Apply an optional 30-minute cap per process:
./experiments/scripts/run_n10000.sh --timeout 1800
```

Strategy names are `tree-none`, `tree-collective`, `sequential-i2`, and
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

Raw runs include metadata, phase/component timings, operation counts, object
sizes, sampled resource use, and `summary.json`. The summary script can also be
invoked on an interrupted campaign to summarize only its successful measured
runs:

```bash
python3 experiments/scripts/summarize.py experiments/results/<campaign-directory>
```

Compare server validity gating/aggregation plus downstream phases separately
from client input encryption, setup, and final threshold decryption. The summary
labels observed server time with its one- or five-input-period scope and keeps
five-period projections separate. Do not describe projected ingestion time as
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

The parameter table records these values. There are four original period grids:
candidate inputs, candidate range masks, delegation inputs, and delegation
range masks. Together they contain `4*T*C` ciphertexts. Encrypted weights,
echo state, keys, and temporaries require additional memory.

For `n=500000`, width 100, and the selected no-refresh profile, `V=326` and
`C=1534`. The four period grids alone contain 30,680 degree-one ciphertexts:
approximately **161 GB (150 GiB) of polynomial coefficients**. That estimate
excludes object overhead, evaluation keys, other live ciphertexts, and garbage
awaiting collection. Benchmark ingestion still retains five-period grids.

The target machine has 300 GB RAM, but the largest cases have not yet been
shown to fit. Run launchers one at a time, inspect measured peak RSS as sizes
increase, and keep any Go runtime/memory environment settings consistent and
recorded when comparing results. The current scripts do not set a memory cap.

## Further work outside this campaign

Remaining work includes repeated and larger fresh-input noise validation,
measured memory feasibility, deployment refresh-noise analysis, and complete
serialized communication accounting. Packing-boundary experiments and broader
parameter searches may help choose faster or smaller profiles later. They are
not additional configurations silently included in the current 75-case matrix.
