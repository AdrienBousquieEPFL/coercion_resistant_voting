# Runtime experiment sets

The active campaign uses the period-streaming masked-input echo implementation,
Lattigo v6.2.0, Go 1.26.1, `b=3`, `T=5`, `qmax=1`, and three multiparty parties.

| Set | k | Voter counts | Strategies | Cases |
|---|---:|---|---|---:|
| `b3-k5` | 5 | 200, 500, 1k, 5k, 10k, 25k, 50k, 100k, 500k, 1M | Sequential, without and with final refresh | 20 |
| `b3-k100` | 100 | 200, 500, 1k, 5k, 10k, 25k, 50k, 100k | Tree and sequential, each without and with final refresh | 32 |

The versioned matrices are `experiments/experiments-b3-k5.csv` and
`experiments/experiments-b3-k100.csv`. `experiments/experiments.csv` contains their
union. Regenerate them with `python3 experiments/scripts/generate_campaigns.py`.
Numeric dimensions remain integers in CSV/JSON. Experiment identifiers, launcher
filenames, campaign directory names, and new raw run directories abbreviate exact
thousands as `1k`, `10k`, etc., and one million as `1M`. Historical files are not renamed.

## Validation status before running

The selected policy is to keep the original `k=5` no-refresh profiles for now:
Q≈416 bits through 50k and Q≈480 bits at 100k–500k. Their synthetic checks at
50k and 500k retained approximately 1.60 and 12.84 bits of noise margin,
respectively, below the 20-bit screening requirement. Those checks stopped
before final tally verification; they did not establish a final-tally mismatch.
An experiment marked `passed` must still complete and verify its decrypted final
tally against the plaintext reference.

The stronger alternatives remain available as
`experiments/parameters/b3-k5/sequential-none-50k.json` (Q≈480 bits) and
`experiments/parameters/b3-k5/sequential-none-500k.json` (Q≈540 bits).
The new 1M profiles, refresh profiles, and `k=100` selections are unchanged. To opt into
them for the first set, regenerate the matrices with:

```bash
python3 experiments/scripts/generate_campaigns.py --strengthen-small-k
```

Running the generator without this flag restores the original-parameter choice.
This does not change any existing parameter JSON. Consult the validation report
for the completed screening coverage. Fresh exact-modulus lattice-security
estimates completed on 2026-09-16: all 16 profiles (nine distinct ring-degree/modulus
pairs), including the stronger alternatives, passed the 128-bit classical target.
The minimum estimate is 133.444 bits under the recorded ADPS16 core-SVP model.
This security check is separate from the noise-margin checks above.

## Run

From `coercion_resistant_voting/`, rebuild with the installed pinned Go toolchain:

```bash
./experiments/scripts/build.sh

# First set (20 configurations).
for n in 200 500 1k 5k 10k 25k 50k 100k 500k 1M; do
  ./experiments/scripts/run_n${n}.sh --set b3-k5 || break
done

# Second set (32 configurations).
for n in 200 500 1k 5k 10k 25k 50k 100k; do
  ./experiments/scripts/run_n${n}.sh --set b3-k100 || break
done
```

Add `--dry-run` to preview commands without FHE execution. For example:

```bash
./experiments/scripts/run_n1M.sh --set b3-k5 --dry-run
./experiments/scripts/run_n100k.sh --set b3-k100 --strategy sequential-final --dry-run
```

The runner also accepts integer counts (`--n 1000000`), `--shape 3,100`, repeated
`--strategy` filters, `--binary`, and `--output-root`. Without `--set` it selects
all configurations for that voter count from the combined matrix. Shape filters
are optional; `--set` is the clearest way to separate the two campaigns.

Defaults are one warm-up per configuration and three measured repetitions for
`n<10k`; one warm-up and one measured repetition for `n>=10k`. Thus the first set
has 56 process executions and the second has 96, totaling 152. `--repeats` overrides
the measurement count. Warm-ups are excluded from summaries. Runs use fresh
processes and independent encryption randomness; workload seeds match across
strategies with the same dimensions and repetition. There is no default timeout;
`--timeout 1800` imposes a 30-minute cap per execution. Any failure stops that
campaign and the shell loops above stop at the failed voter count.

## Measurement scope

Below 10k, all voters may submit across five periods. At 10k and above, benchmark
mode freshly encodes and encrypts inputs for all n sampled voters in period zero;
other periods have no submissions, but all five periods initialize accumulators,
close echo, and execute the downstream tally. Client preparation is separately
timed and excluded from measured server ingestion.

The projected five-period tally equals accumulator initialization + measured
server ingestion times five + observed downstream server tally + collective
refresh. The projection multiplies ingestion only. It is not a measured
five-period full-electorate runtime. Summaries also retain observed tally time
with its one-input-period scope. Setup and final threshold decryption are outside
the tally metric. Multiparty phase timing overlaps containing phases, so the
summarizer subtracts it before explicitly adding refresh; do not double count it.

Memory is the observed whole-process OS peak RSS, including setup and client
preparation. A single measured run provides no estimate of variability.
Timing runs use final-only correctness diagnostics, without secret-assisted noise
checks. Benchmark workloads do not prove correctness for all election schedules.

## Circuit depth and packing

Both sets have the same ciphertext multiplication depth because the majority
polynomial depends on T=5, not k. The masked-input leaf has depth 1; the midpoint
tree's total has depth 4, and sequential echo has depth 5. The degree-five
majority polynomial adds three layers, encrypted weight multiplication adds one,
and the final weighted-vote multiplication adds one.

| Mode | Echo depth | Downstream depth | Without refresh | Longest segment with final refresh |
|---|---:|---:|---:|---:|
| Tree | 4 | 5 | 9 | 5 |
| Sequential | 5 | 5 | 10 | 5 |

These are dependency depths, not the number of Q primes consumed. The invariant
BGV multiplications in this implementation preserve levels. Additions, plaintext
multiplications, rotations, and key switching contribute noise too; depth alone
cannot determine a sufficient modulus. Every selected file has `Q mod t = t-1`
to keep the invariant multiplication scale factor one.

Final refresh runs after echo, before majority selection, on both component
totals (2*C ciphertexts). Tree uses interval 0; sequential uses interval T=5,
which suppresses intermediate callbacks. No additional refresh boundary or
change to the mathematical tally relation is introduced.

Packing width is `max(b,k)` with two BGV rows. For N=32768, width 5 packs 6,552
voters per ciphertext; width 100 packs 326. At 100k, that is 16 versus 307 blocks.
At N=16384, width 100 packs 162 voters; 50k needs 309 blocks. Larger k therefore
costs many more ciphertexts and rotations despite unchanged depth. Reducing k
to 50 at N=32768 would pack 654 voters, or 153 blocks at 100k, approximately
halving block-based work. k=100 remains the chosen second set; compact noise
screens are not full-electorate runtime or memory measurements.

## Parameters and validation

See `experiments/B3_PARAMETER_VALIDATION.md` for exact selected budgets,
noise-screen outcomes, security assumptions, rejected candidates, and limitations.
The new 1M plaintext modulus is 1,179,649, greater than n*qmax and compatible
with full batching at N=32768. The old modulus 786,433 cannot cover one million.
Parameter JSONs contain exact decimal-string Q/P primes and version information;
Go records a canonical parameter identifier in every run's metadata.

The synthetic screen uses a copied source tree, compact encrypted aggregates,
and residual-noise amplification for target packing occupancy and cross-block
reductions. It requires all enabled plaintext checks and at least 20 bits at
recorded noise checkpoints. This is empirical stress evidence, not a formal
worst-case noise bound or a complete independent-encryption full-election test.
The prototype uses ordinary refresh error noise; deployment flooding and complete
protocol security are outside these checks.

## Results and reproducibility

With `--set`, results are written under `experiments/results/<set>/`, in a new
`n10k-v2-<UTC timestamp>/` directory. Collisions receive a suffix; existing results
are never overwritten. Each campaign retains `campaign.json`, `executions.csv`,
`measurements-summary.csv`, and per-run logs/raw CSV/JSON files. Absolute paths in
archived execution manifests may refer to the experiment host.

`experiments/results/` remains git-ignored as requested. The Rabat archive is
unchanged. Keep the binary hash, source revision, parameters, metadata, and
warm-up/measured labels with any exported results. Parameter-validation files
outside results are separate from runtime measurements.

Existing plotting scripts describe historical b=k=5 data and should not be used
to mix the two new shapes without adapting their dimension checks and captions.
No historical plotted values are replaced by the new matrices.
