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
- encrypted candidate and delegation range masks;
- periodic echo updates for missing submissions;
- tree-based and sequential echo calculations;
- collective refresh to reduce ciphertext noise;
- majority selection, delegation, weighted voting, and packed aggregation.

Credential validity is not implemented yet. Therefore, validity bits do not yet
control whether range masks are included.

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
| `--echo-refresh-interval` | `1` | Number of sequential updates between refreshes |

### Echo strategies

Tree mode combines periods in a balanced tree. Its multiplication depth is
`ceil(log2(T))`. Afterward, the parties collectively refresh the candidate and
delegation totals:

```bash
go run . --echo-mode=tree
```

The refresh-interval flag is not used in tree mode. The program records it as
zero in the run metadata.

Sequential mode processes the periods in order using these equations:

```text
u^p     = u^(p-1) * (1 - z^p) + input^p
total^p = total^(p-1) + u^p
```

The parties refresh the current value after the selected number of updates:

```bash
# Refresh the current candidate and delegation values after every update.
go run . --echo-mode=sequential --echo-refresh-interval=1

# Refresh after every two updates.
go run . --echo-mode=sequential --echo-refresh-interval=2
```

Both modes refresh the final echo totals before majority selection. Both use the
same encrypted inputs, encrypted range masks, plaintext checks, and remaining
tally steps.

## Results and instrumentation

Every run creates a new timestamped directory under `runs/`. It contains:

- the parameters used for the run;
- time spent in each phase;
- operation counts;
- ciphertext and key sizes;
- CPU and memory measurements; and
- crash information if the run fails.

`meta.json` records the echo mode and refresh interval. In `ops.csv`, the input
phase's `EncryptNew` count includes the range-mask encryptions. Echo and refresh
operations are also counted there.

Each run creates new random inputs. A single run is useful for checking that the
program works, but it is not a fair performance comparison with earlier runs.

The refresh code currently uses `params.Xe()` for extra noise, as in Lattigo's
tests. This is suitable for the current prototype. A real deployment must choose
and document a secure noise-flooding setting.

## Validation

```bash
gofmt -w main.go helpers.go instrumentation.go multiparty_helpers.go test.go
go test ./...
```
