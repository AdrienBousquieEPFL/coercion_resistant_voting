#!/usr/bin/env python3
"""Generate the two b=3 experiment matrices from selected concrete parameters."""
import argparse
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COUNTS = (200, 500, 1000, 5000, 10000, 25000, 50000, 100000, 500000, 1000000)


def count_label(n):
    if n >= 1000000 and n % 1000000 == 0:
        return f'{n // 1000000}M'
    if n >= 1000 and n % 1000 == 0:
        return f'{n // 1000}k'
    return str(n)


def campaign_rows(k, strengthen_small_k=False):
    rows = []
    for n in COUNTS:
        if k == 100 and n > 100000:
            continue
        for mode in (('sequential',) if k == 5 else ('tree', 'sequential')):
            for refresh in (False, True):
                strategy = f"{mode}-{'final' if refresh else 'none'}"
                if k == 100:
                    parameter = f"b3-k100/{strategy}-{'50k' if n <= 50000 else '100k'}.json"
                elif strengthen_small_k and not refresh and n < 1000000:
                    parameter = f"b3-k5/{strategy}-{'50k' if n <= 50000 else '500k'}.json"
                elif n == 1000000:
                    parameter = f'b3-k5/{strategy}-1M.json'
                else:
                    parameter = f"aligned-final/{strategy}-t{65537 if n <= 50000 else 786433}.json"
                rows.append(dict(experiment_id=f'n{count_label(n)}-b3-k{k}-{strategy}', n=n, b=3, k=k, T=5,
                                 qmax=1, parties=3, strategy=strategy, echo_mode=mode,
                                 refresh_mode='collective' if refresh else 'none',
                                 refresh_interval=5 if refresh and mode == 'sequential' else 0,
                                 execution_mode='benchmark' if n >= 10000 else 'fresh',
                                 sample_voters=n if n >= 10000 else 0, parameter_file='parameters/' + parameter))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strengthen-small-k', action='store_true',
                        help='opt into stronger small-k no-refresh profiles; default preserves the requested existing parameters')
    args = parser.parse_args()
    sets = [campaign_rows(5, args.strengthen_small_k), campaign_rows(100)]
    for filename, rows in [('experiments-b3-k5.csv', sets[0]), ('experiments-b3-k100.csv', sets[1]),
                           ('experiments.csv', sets[0] + sets[1])]:
        with (ROOT / filename).open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0], lineterminator='\n')
            writer.writeheader()
            writer.writerows(rows)


if __name__ == '__main__':
    main()
