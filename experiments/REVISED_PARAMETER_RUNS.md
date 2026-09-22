# Rerun the revised sequential parameter profiles

These standalone matrices select only the five newly requested configurations.
They do not modify the original matrices or regenerate earlier measurements.

| Set | n | Strategy | N | Q bits | QP bits | t |
|---|---:|---|---:|---:|---:|---:|
| b3-k5-revised | 1M | sequential-none | 32768 | 495 | 556 | 1179649 |
| b3-k100-revised | 100k, 500k | sequential-none | 32768 | 480 | 541 | 786433 |
| b3-k100-revised | 100k, 500k | sequential-final | 16384 | 312 | 342 | 786433 |

All use b=3, T=5, three parties, one warm-up and one measured run. Fresh input
aggregation is sampled for n voter-period submissions and projected to five
periods, as in the existing campaigns. Every included run verifies its final
tally. No-refresh profiles accept lower synthetic noise margins; these are not
worst-case correctness guarantees. See LOW_MARGIN_1M.md, LOW_MARGIN_K100.md and
K100_PROFILE_REVIEW.md and their corresponding JSON evidence files.

## Files to commit

From the repository root, stage this exact runnable package:

```bash
git add -- \
  experiments/scripts/run_campaign.py \
  experiments/scripts/test_revised_campaign.py \
  experiments/experiments-b3-k5-revised.csv \
  experiments/experiments-b3-k100-revised.csv \
  experiments/parameters/b3-k5/sequential-none-1M-low-margin.json \
  experiments/parameters/b3-k100/sequential-none-100k-500k-low-margin.json \
  experiments/parameters/b3-k100/sequential-final-100k-500k-smaller-ring.json \
  experiments/REVISED_PARAMETER_RUNS.md
```

Also commit the compact validation evidence for reproducibility:

```bash
git add -- \
  experiments/LOW_MARGIN_1M.md experiments/low-margin-1M-validation.json \
  experiments/LOW_MARGIN_K100.md experiments/low-margin-k100-validation.json \
  experiments/K100_PROFILE_REVIEW.md experiments/k100-profile-review.json
```

Inspect the complete staged diff (including anything already staged):

```bash
git diff --cached --stat
git diff --cached
git commit -m "Add revised parameter rerun campaigns through 500k for k100"
git push
```

No new Go files, dependency changes, results, figures, executable binaries, or
local validation directories are needed for this update. Existing tracked runner
dependencies (generate_campaigns.py, summarize.py and launchers) must be present
in the remote checkout. Do not run generate_campaigns.py to select these profiles:
the dedicated revised CSVs are supplied directly.

## Remote preparation

In the remote repository, pull the commit and rebuild with preinstalled Go 1.26.1:

```bash
git pull --ff-only
./experiments/scripts/build.sh
```

Building is a reproducibility precaution; the parameter loader and Go tally did
not change in this update. The build script does not download dependencies.

## k100: 100k and 500k, both sequential modes

```bash
for n in 100k 500k; do
  ./experiments/scripts/run_n${n}.sh --set b3-k100-revised || break
done
```

To run modes independently, use `--strategy sequential-none` or
`--strategy sequential-final`, for example:

```bash
./experiments/scripts/run_n500k.sh --set b3-k100-revised --strategy sequential-final
```

## k5: 1M, no refresh, separately

```bash
./experiments/scripts/run_n1M.sh --set b3-k5-revised
```

Append `--dry-run` to any launcher command to inspect without executing FHE.
Results go under `experiments/results/b3-k100-revised/` and
`experiments/results/b3-k5-revised/`. Each invocation has a fresh timestamped
campaign directory and its own measurements-summary.csv. Rerunning a command
creates new measurements; it does not resume an interrupted campaign.

Keep the new results separate from the old profiles when plotting. The current
plotter's --refresh-results overlay only replaces k5 refresh points; it does not
automatically merge these new no-refresh and k100 revisions.
