# Coercion-resistant voting FHE prototype

This Go program simulates the encrypted voting tally with Lattigo and BGV. It:

1. creates test voting data;
2. lets several parties create a shared public key;
3. encrypts the inputs with that key;
4. computes the tally on encrypted data;
5. lets the parties decrypt the final result together; and
6. checks the result against the same calculation in plaintext.

The program currently supports:

- encrypted voter weights;
- encrypted candidate and delegation votes;
- one encrypted mask per submission, shared by both vote types;
- periodic echo updates for missing submissions;
- tree-based and sequential echo calculations;
- collective refresh to reduce ciphertext noise;
- an optional no-refresh mode for parameter experiments;
- majority selection, delegation, weighted voting, and packed aggregation.

The protocol assumes voters commit to pre-encrypted ciphertexts for all voting
possibilities and their corresponding masks. That commitment mechanism is
outside this implementation. The simulation freshly encrypts the selected
inputs under the collective public key, then adds them directly to the period
tally. There are no validity-bit inputs or validity-gating multiplications.

Each regular simulation submission contains one-hot candidate and delegate
votes and a single encrypted mask of ones covering the full `max(b,k)` voter
block. Both components use `randomVotingVector` to generate a nonzero choice
in every period. No zero-vote or missing-submission scenarios are injected.
The sampled benchmark retains its encrypted-zero fixtures for timing.

All-zero payloads with a zero mask are intended as an anti-coercion mechanism
and are outside the evaluation workload. Whether a zero component with mask
one is permitted by the final protocol remains undecided. Low-level helpers
and tests retain these arithmetic cases without establishing protocol
admissibility or validating coercion resistance.

## Setup

The project uses Go 1.26.1 and Lattigo v6.2.0. Download the versions listed in
`go.mod`:

```bash
go mod download
```

## Running

Run the default experiment. It uses 100 voters, 5 candidates, 5 delegates, 5
periods, 3 decryption parties, and tree echo mode:

```bash
go run .
```

Progress output can be disabled without changing the experiment:

```bash
go run . --progress=false
```

You can change these parameters:

| Flag | Default | Meaning |
|---|---:|---|
| `--n` | `100` | Number of voters |
| `--b` | `5` | Number of candidates |
| `--k` | `5` | Number of delegates |
| `--T` | `5` | Odd number of voting periods |
| `--qmax` | `1` | Largest initial voter weight used in the test data |
| `--N` | `3` | Number of parties that create keys and decrypt together |
| `--progress` | `true` | Show progress on stderr |
| `--echo-mode` | `tree` | Echo method: `tree` or `sequential` |
| `--refresh-mode` | `collective` | Refresh strategy: `collective` or `none` |
| `--echo-refresh-interval` | `1` | Number of sequential updates between refreshes |
| `--diagnostic-checks` | `all` | Threshold-decryption checks: `all` or `final` |
| `--metrics-sample-interval` | `1s` | Interval for phase-level CPU and memory samples |

### Echo strategies

Both modes collect one period at a time into three encrypted-zero accumulators
(candidate payload, delegation payload, and shared mask). Submissions are
added on arrival. At period close, echo consumes those accumulators
before the next period is initialized. No array of all periods' ciphertexts is
retained; the simulation still prepares plaintext schedules in advance.

Tree mode incrementally combines completed periods in a balanced tree. It uses
the same midpoint grouping as the previous batch implementation: for `T=5`,
`((P1,P2),P3)` is combined with `(P4,P5)`. A subtree is merged as soon as its
last period closes, retaining only a logarithmic number of partial segments.
No extra prefix tally is evaluated at intermediate period boundaries. Its multiplication depth is
`ceil(log2(T))`. In collective mode, the parties afterward refresh the
candidate and delegation totals:

```bash
go run . --echo-mode=tree
```

The refresh-interval flag is not used in tree mode. The program records it as
zero in the run metadata.

At period close, each aggregated candidate/delegation payload is multiplied
by the aggregated shared mask. Tree leaves use this gated payload too.
Sequential mode processes the periods in order using these equations:

```text
u^p     = u^(p-1) * (1 - z^p) + input^p * z^p
total^p = total^(p-1) + u^p
```

The parties refresh the current value after the selected number of updates:

```bash
# Refresh the current candidate and delegation values after every update.
go run . --echo-mode=sequential --echo-refresh-interval=1

# Refresh after every two updates.
go run . --echo-mode=sequential --echo-refresh-interval=2
```

In collective refresh mode, both echo strategies refresh the final echo totals
before majority selection. Both strategies use the same encrypted inputs,
the shared encrypted mask, plaintext checks, and remaining tally steps.

### No-refresh experiments

The current `LogN=14` parameters use `logQ=377` and `logP=61`, for
`logQP=438`. This matches the modulus budget of Lattigo's 128-bit-security
example while keeping the same eight Q limbs and one P limb.

For the default five-period tree experiment, the program can complete without
an interactive refresh:

```bash
go run . --echo-mode=tree --refresh-mode=none
```

This mode also disables intermediate sequential refreshes and ignores
`--echo-refresh-interval`. It is an experimental option, not a guarantee that
every larger value of `n`, `T`, or `qmax` has enough noise budget. Collective
mode remains the default.

### Diagnostic checks

The default `--diagnostic-checks=all` threshold-decrypts and checks intermediate
ciphertexts to identify errors during development. These decryptions are not
part of the intended tally protocol. For runtime and memory experiments, use:

```bash
go run . --diagnostic-checks=final
```

Final mode skips every intermediate threshold decryption and does not allocate
the full `n*b` and `n*k` plaintext echo-reference vectors. It performs one
threshold decryption of the completed tally and compares that decoded result
with a memory-light reference computed directly from the period schedules. The
selected mode is recorded in `meta.json`.

### Sampled server benchmark

Normal `go run .` execution independently encodes and encrypts incoming client
inputs. Use normal execution for correctness, communication, and noise-budget
experiments.

The separate `benchmark` command estimates large-election server cost without
executing the repeated aggregation for every voter and period:

```bash
go run . benchmark --n=500000 --sample-voters=1000 --progress=false
```

It independently encodes and encrypts real candidate/delegation inputs and
shared masks for the sampled voters in period zero. Client preparation is timed
separately and excluded from the server aggregation sample. The measured
aggregation time is projected to `n*T`; accumulator initialization and echo are
executed for all T periods, followed by the complete downstream tally.

Later periods receive no submissions: their encrypted-zero accumulators enter
echo, which carries the accepted first-period choices. Unsampled voters have no
submission in any period. Final correctness uses this actual schedule, not an
all-zero expected result. The campaign uses `--sample-voters=n` and final-only
diagnostics; explicit `--diagnostic-checks=all` or `--noise-check` can check the
sampled workload, but cannot establish full-election noise correctness.

New metadata uses `execution_mode=sampled-fresh-input-benchmark`. Older
`sampled-server-benchmark` runs reused a zero fixture and are not directly
comparable. Encryption now takes real process time and affects memory/cache/GC,
even though its timer is excluded from server aggregation. Keep old results and
figures as historical; rebuild before running new experiments. The projection
assumes representative submissions and linear aggregation scaling.

## Results and instrumentation

Every run creates a new timestamped directory under `runs/`. It contains:

- the parameters used for the run;
- time spent in each phase;
- operation counts;
- ciphertext and key sizes;
- CPU and memory measurements; and
- crash information if the run fails.

`summary.json` contains the process-wide peak RSS reported by the operating
system. Use `process_peak_rss_mib` as the headline memory-footprint result: it
is a high-water mark rather than a periodic sample, so it also captures short
memory spikes. Run each measured configuration in a fresh process.

`components.csv` separates the streamed-input phase into lightweight timing
totals for encrypted-zero aggregate initialization, simulated client
encoding/encryption, and server-side aggregation. These
component timers do not force garbage collection or create phase boundaries in
the per-voter loop. They are non-overlapping parts of Phase 4.1 and must not be
added to the full phase time again. Their sum can be slightly smaller than the
outer phase because ordinary loop, packing, progress, and instrumentation
overhead is not assigned to a component.

Multiparty protocols are recorded separately in `components.csv` as
`multiparty:refresh`, `multiparty:public-key-generation`,
`multiparty:relinearization-key-generation`, `multiparty:galois-key-generation`,
`multiparty:threshold-decryption`, and, when enabled,
`multiparty:diagnostic-threshold-decryption`. Repeated calls accumulate into one
row per protocol. These measure whole local executions, including party and
coordinator work; they do not measure network latency or parallel party time.

`phases.csv` keeps inclusive `wall_ms` and `cpu_ms` and adds
`multiparty_wall_ms` and `multiparty_cpu_ms` for protocol work inside each phase.
These are overlapping measurements, not additional costs to add to the phase.

The campaign summary reports both server-only computation and a tally time
that includes refresh:

- `server_observed_wall_ms:<scope>`: accumulator initialization plus server
  aggregation plus phases 4.2–4.7 minus their multiparty time.
- `tally_refresh_wall_ms`: all intermediate and final collective refresh calls.
- `tally_observed_wall_ms:<scope>`: the server metric plus refresh time.

Here `<scope>` is `five_input_periods` for normal execution or `one_input_period`
for benchmark ingestion; downstream computation and initialization still cover
all T periods. Benchmark five-period projections have separate
`server_projected_wall_ms:five_input_periods` and
`tally_projected_wall_ms:five_input_periods` metrics. Setup and final threshold
decryption remain separate from both tally metrics. Simulated client input
preparation is excluded. Use final-only diagnostics and disable noise checks
for runtime measurements; other diagnostic and instrumentation overhead is not
fully removed by these component timers.

Historical files without multiparty timing columns cannot be separated after
the fact. Their old server estimates are emitted only with a
`legacy_server_inclusive_multiparty_excluding_initialization_...` name.

The default one-second background sampling interval is intended only to show
approximately which phase caused the memory peak. A shorter interval such as
`--metrics-sample-interval=250ms` can be used for dedicated detailed profiling,
but compared runs should use the same interval.

`meta.json` records the echo mode, refresh mode, and refresh interval. The
streamed-input phase counts payload/shared-mask encryption and additions. The
`input_ciphertexts_received` row in `objects.csv` estimates total input traffic
for all three ciphertexts per submission, including all-zero submissions;
these ciphertexts are not all live at once. Benchmark samples use the separate
`sampled_input_ciphertexts` row. Echo and refresh operations are also counted.

Each run creates new random inputs. A single run is useful for checking that the
program works, but it is not a fair performance comparison with earlier runs.

The refresh code currently uses `params.Xe()` for extra noise, as in Lattigo's
tests. This is suitable for the current prototype. A real deployment must choose
and document a secure noise-flooding setting.

## Validation

```bash
gofmt -w *.go
go test ./...
```

The deterministic unit tests cover shared-mask replacement, all-zero-submission
echo, balanced-versus-sequential echo results, and the first packing boundary
that requires more than one ciphertext.


## Runtime experiment campaign

The 36-configuration campaign, exact-prime parameter files, per-`n` launchers,
and parameter-screening workflow are documented in
[`EXPERIMENTS.md`](EXPERIMENTS.md). Benchmark ingestion starts at
`n=10000` and covers all voters for one period, with `T=5` downstream.
The current scope is `b=k=5`: both no-refresh modes at every selected voter
count, plus tree and sequential final-refresh cases only at 10,000 and 50,000.

Use `--parameter-file=<file>` for a concrete versioned profile,
`--workload-seed=<seed>` to repeat simulated inputs, and `--output-root=<dir>`
for uniquely named result directories. Keys and encryption remain freshly
random. `--noise-check` is an opt-in, secret-assisted diagnostic for synthetic
experiments; it enables all plaintext checks and must not be used for timing
when reporting benchmark timings. `--describe-parameters` prints a concrete
profile without generating keys or running the tally.

Period streaming is identified by `tally_flow=period-streaming-shared-mask-v2`
in historical run metadata. New masked-input echo runs use
`tally_flow=period-streaming-masked-echo-v3`. Phases 4.1 and 4.2 repeat for successive periods (with an
additional 4.2 interval for final refresh when enabled). Sum repeated phase
rows within a run; the campaign summary does this before calculating medians
across runs. Phase instrumentation performs its usual GC at each boundary,
so timing results should not be pooled with the older batch implementation.

Earlier results and the checked-in parameter table describe the previous
validity-gated flow and are retained as historical evidence. Regenerate cost
tables and rerun experiments before comparing performance with this revision;
FHE parameter files have not been retuned by this change.
