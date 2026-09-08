# Parameter review of the shared-mask tally

Follow-up: concrete, empirically screened parameters are now available in
[FINAL_PARAMETER_VALIDATION.md](FINAL_PARAMETER_VALIDATION.md). The unresolved
status below concerns a fully analytical noise bound, not the availability of
usable screened parameter files. The campaign now uses final refresh only.

Review date: 2026-09-08. Scope: the current working tree, Lattigo v6.2.0,
`b=k=5`, `T=5`, `qmax=1`, three parties, and a 128-bit classical security target.
The requested refresh policy is **one boundary after echo, for both modes**.
That boundary refreshes both candidate and delegation totals, so it involves
`2*C` ciphertext refreshes, where `C` is the number of packed voter blocks.

**Status: structural review complete; numerical Q/P selection remains unresolved.**
The earlier analytical discussion was a proposed workflow, not a validated
Lattigo noise model. Existing parameter files and historical empirical checks
must not be described as analytically validated for this refactored circuit.
No new executable parameter sets are supplied by this review.

## Four parameter families

| Family | Echo depth | Depth after echo | Longest path without refresh | Refresh policy |
| --- | ---: | ---: | ---: | --- |
| tree-none | 3 | 5 | 8 | none |
| sequential-none | 4 | 5 | 9 | none |
| tree-final-refresh | 3 | 5 | 5 | completed echo totals only |
| sequential-final-refresh | 4 | 5 | 5 | completed echo totals only |

These are ciphertext multiplication depths, **not consumed Q primes or noise
bits**. Scale-invariant multiplication preserves levels. The downstream depth
includes three layers for the degree-five majority polynomial, one encrypted
weight multiplication, and the final weighted-vote multiplication.

Existing CLI settings for final-only refresh at `T=5` are:

```text
tree:       --echo-mode=tree       --refresh-mode=collective --echo-refresh-interval=0
sequential: --echo-mode=sequential --refresh-mode=collective --echo-refresh-interval=5
```

The sequential callback in `main.go` accepts only interior periods, so interval
5 prevents all intermediate refreshes. Setting interval 0 is rejected for
collective sequential mode. This review does not change the runnable campaign:
`experiments.csv` still contains the previous interval-2/3 configurations.

## What the refactor changes

`streamAndAggregatePeriodInputs` in `tally_inputs.go` now initializes three
encrypted-zero accumulators per packed block per period: candidate payload,
delegation payload, and the shared mask. Each submitted ballot supplies three
ciphertexts, which are added directly. There are **no encrypted validity-gate
multiplications** in this input path. Older four-grid/gated-input estimates do
not describe it.

For ring degree `R=2^logN`, full batching, and width 5:

```text
V = 2 * floor((R/2)/5)       voters per ciphertext
C = ceil(n/V)               ciphertext blocks per component
m = min(n,V)                maximum submissions accumulated in one block
```

At logN=14, `V=3276`; at logN=15, `V=6552`. Increasing n within one block
increases its addition fan-in. Beyond that, n principally increases C, the
cross-block reductions, and eventually the required plaintext modulus. It does
not increase the echo multiplication depth.

Across both channels, the echo code executes:

| Operation | Tree | Sequential |
| --- | ---: | ---: |
| Ciphertext multiplications, each with relinearization | `8*C*(T-1)` | `2*C*(T-1)` |
| Ciphertext additions in echo composition | `8*C*(T-1)` | `4*C*(T-1)` |

In addition, both modes construct `1-mask` separately for the two channels:
`2*T*C` scalar negations and `2*T*C` plaintext-vector additions. These are not
included in the ciphertext-addition row. Tree mode computes all four state
components even at the root, although only its `d` component is returned.

After echo, there are `2*C` polynomial evaluations and `3*C` explicit ciphertext
multiplications outside the polynomial evaluator. Rotations, plaintext products,
scale matching, and reductions also contribute noise. The polynomial counts
reported by `CountPolyEvalOps` are explicitly estimates and must not be treated
as an exact polynomial-operation trace.

The current random delegation matrix has one selected voter per delegate column,
in distinct rows. Consequently, its sparse encrypted/public-matrix stage performs
k nonzero contributions in total, rather than n*k nonzero contributions.

## Noise propagation required for selection

A circuit model must carry the ciphertext's level, exact scale modulo t, error
bound in a specified norm, and plaintext coefficient information. Slot values
bounded by one do not imply polynomial coefficients bounded by one.

For a fixed-scale addition, a deterministic bound is
`B_out <= B_left + B_right`. If scale matching multiplies the operands by
`r_left` and `r_right`, the bound must include those actual multipliers.
Plaintext multiplication requires a ring-product bound; for example,
`||p*e||_infinity <= ||p||_1 * ||e||_infinity`.

An initial per-period accumulator has an encryption of zero plus up to m input
ciphertexts. Its bound must include all those errors. A square-root-of-m estimate
requires a justified stochastic model. In benchmark mode, input reception reuses
the same encrypted-zero fixture: its contribution is **m times the same error**,
not a sum of independent errors. Parameter selection for genuine elections must
also cover nonzero plaintexts and all periods; the benchmark fixture cannot
validate that requirement.

Use the following actual dependency recurrences, with noise propagation on every
addition and multiplication:

```text
Sequential:
  current' = current * (1-mask) + input
  total'   = total + current'

Tree (left segment followed by right segment):
  a = right.a * left.a
  b = right.a * left.b + right.b
  c = left.c + right.c * left.a
  d = left.d + right.d + right.c * left.b
```

The shared mask and reused tree operands create correlations. Do not assume
independent errors at each occurrence of an operand. The current fully submitted
workload makes many carry terms zero in plaintext, but their ciphertext errors
remain and the multiplication still executes.

In Lattigo's `schemes/bgv/evaluator.go`, invariant tensoring updates scale as:

```text
s_out = s_left * s_right / (-Q mod t) mod t
```

Therefore the exact primes matter, not just log2(Q). Its `quantize` routine divides
in an auxiliary multiplication basis before multiplying by t; the rounding bound
must describe that implementation. The auxiliary `RingQMul` basis is distinct
from the P basis used by evaluation keys. A promising search constraint is
`Q = -1 mod t`, which makes the multiplication scale factor one. This is a search
idea, not a proof that a proposed modulus is sufficient.

Final refresh requires the incoming echo totals to be decryptable. It does not
repair an already incorrect echo result. Model both the input requirement and
the output error of the collective refresh protocol. Refresh preserves metadata,
including scale, so it must not be modeled as an arbitrary reset to scale one
and zero noise. The final threshold-decryption key switch also adds noise.

## Remaining numerical work

Before selecting smaller Q/P chains, establish compatible bounds for:

1. Collective-public-key encryption and encrypted-zero initialization.
2. Invariant tensoring and its RNS rounding, relinearization, and rotations using
   the actual collective evaluation-key distributions and decomposition.
3. Exact polynomial coefficient/scaling operations and downstream reductions.
4. Collective refresh input tolerance and output error, and final key switching.

Lattigo's `NoiseFreshPK` and multiparty noise helpers provide standard-deviation
estimates for particular primitives. They are not interchangeable with uniform
coefficient bounds for the full correlated computation. A stochastic selector
would additionally need an explicit whole-run failure probability, including
all coefficients, blocks, and refreshes.

Once those bounds exist, search `(logN,t,Q,P)` per n and family. Require t to cover
the plaintext result (`t > n*qmax` here), support the chosen batching layout,
and permit interpolation at 0 through T. Preserve the loader's minimum of four
Q primes; that structural restriction does not establish noise sufficiency.
Propagate the full circuit, including both sides of a refresh boundary, and keep
a stated correctness margin. Then assess the **exact Q*P** modulus against the
128-bit target under the documented secret/error distribution and attack model.
The [lattice estimator](https://github.com/malb/lattice-estimator) estimates attack
costs; it does not determine whether the tally can decrypt correctly.

Separate families can ultimately select identical parameters if the bounds give
the same optimum. Final refresh does not by itself imply that the tree and
sequential families need different Q values, or that they can safely share them.

## Reproducing the structural table

```bash
python3 experiments/scripts/analytical_requirements.py
python3 experiments/scripts/analytical_requirements.py --n 200 500000 --logN 14
```

The default output covers nine voter counts, two candidate ring degrees, and four
families: 72 structural rows. It reports no numerical Q/P recommendation and
does not write parameter files, change the campaign, or execute an FHE tally.
The companion `analytical-requirements.csv` is that default output.

Source references: `tally_inputs.go`, `periodic_echo.go`, `main.go`,
`experiment_parameters.go`, `helpers.go`; pinned Lattigo files
`schemes/bgv/{encoder,evaluator}.go`,
`circuits/common/polynomial/polynomial_evaluator.go`,
`circuits/bgv/polynomial/polynomial_evaluator_sim.go`, and `multiparty/utils.go`.

## Checks performed

Ran `python3` inline assertions against the requirements module: packing at
logN 14/15, tree depths for 1/2/5/8/9 periods, T=5 echo operation counts,
all four refresh/depth combinations, absence of intermediate refreshes under
the proposed CLI settings, unique coverage of all 72 rows, and CLI rejection
of n=0. All passed. Generated the CSV with the script's default arguments.
`git diff --check` also passed. No Go tests, encrypted tally, runtime benchmark,
or new lattice-security estimation was run for this structural review.
