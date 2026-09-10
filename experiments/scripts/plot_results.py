#!/usr/bin/env python3
"""Plot successful measured runs; resolve copied raw directories locally.
Requires matplotlib. No timing measurements or source results are changed.
"""
import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter

LABELS = {'tree-none': 'Tree · no refresh', 'sequential-none': 'Sequential · no refresh',
          'tree-final': 'Tree · final refresh', 'sequential-final': 'Sequential · final refresh'}
COLORS = ['#2266aa', '#d97919', '#21866b', '#9956a6']


def read_csv(path):
    with path.open() as f:
        return list(csv.DictReader(f))


def load_runs(root):
    runs, skipped, seen = [], [], set()
    for campaign in sorted(root.iterdir()):
        if not campaign.is_dir():
            continue
        executions = campaign / 'executions.csv'
        if not executions.exists():
            skipped.append(campaign.name + ': no executions.csv')
            continue
        config = json.loads((campaign / 'campaign.json').read_text())
        configs = {c['experiment_id']: c for c in config['configurations']}
        for entry in read_csv(executions):
            if entry['run_kind'] != 'measured' or entry['status'] != 'passed':
                continue
            raw = campaign / 'raw' / Path(entry['run_directory']).name
            if raw.name in seen:
                raise ValueError('Duplicate run: ' + raw.name)
            seen.add(raw.name)
            meta = json.loads((raw / 'meta.json').read_text())
            cfg = configs[entry['experiment_id']]
            assert (meta['b'], meta['k'], meta['T'], int(cfg['parties'])) == (5, 5, 5, 3)
            phases = read_csv(raw / 'phases.csv')
            components = defaultdict(float)
            for r in read_csv(raw / 'components.csv'):
                components[r['component']] += float(r['wall_ms'])
            downstream = sum(float(r['wall_ms']) - float(r['multiparty_wall_ms'])
                             for r in phases if r['phase'].startswith(tuple(f'4.{i}-' for i in range(2, 8))))
            benchmark = entry['execution_mode'] == 'benchmark'
            ingestion = '4.1-estimated-full-server-aggregation' if benchmark else '4.1-server-aggregation'
            assert ingestion in components and '4.1-aggregate-initialization' in components
            tally = components['4.1-aggregate-initialization'] + components[ingestion] + downstream + components['multiparty:refresh']
            runs.append(dict(campaign=campaign.name, run=raw.name, n=meta['n'], strategy=entry['strategy'],
                             repetition=entry['repetition'], parameter_id=meta['parameter_id'], hostname=meta['hostname'],
                             git_sha=meta['git_sha'], input_execution_mode=meta['execution_mode'], runtime_scope='five-period projection' if benchmark else 'five-period observed',
                             tally_seconds=tally / 1000, peak_rss_gib=float(entry['process_peak_rss_mib']) / 1024))
    if not runs:
        raise ValueError('No successful measured runs')
    if len({r['hostname'] for r in runs}) != 1 or len({r['git_sha'] for r in runs}) != 1:
        raise ValueError('Mixed machines or revisions; separate results before plotting')
    return runs, skipped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, default=Path(__file__).resolve().parents[1] / 'results')
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parents[1] / 'figures')
    parser.add_argument('--only-minutes', action='store_true', help='Generate only the additional minutes plot')
    args = parser.parse_args()
    runs, skipped = load_runs(args.results)
    groups = defaultdict(list)
    for r in runs:
        groups[(r['strategy'], r['n'])].append(r)
    points = []
    for (mode, n), rows in sorted(groups.items()):
        assert len({r['parameter_id'] for r in rows}) == 1
        p = dict(strategy=mode, n=n, repetitions=len(rows), runtime_scope=rows[0]['runtime_scope'])
        for metric in ['tally_seconds', 'peak_rss_gib']:
            values = [r[metric] for r in rows]
            p.update({metric + '_median': statistics.median(values), metric + '_min': min(values), metric + '_max': max(values)})
        points.append(p)
    args.output.mkdir(parents=True, exist_ok=True)
    for filename, rows in ([] if args.only_minutes else [('plotted-runs.csv', runs), ('plotted-summary.csv', points)]):
        with (args.output / filename).open('w') as f:
            writer = csv.DictWriter(f, fieldnames=rows[0], lineterminator='\n')
            writer.writeheader(); writer.writerows(rows)
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 11, 'axes.spines.top': False,
                         'axes.spines.right': False, 'svg.fonttype': 'none'})
    counts = sorted({p['n'] for p in points})
    repetitions = sorted({p['repetitions'] for p in points})
    repetition_label = str(repetitions[0]) if len(repetitions)==1 else f'{repetitions[0]}–{repetitions[-1]}'
    for metric, filename, title, ylabel, divisor in [
        ('tally_seconds', 'runtime-by-voters', 'Tally runtime by number of voters', 'Tally wall time (seconds)', 1),
        ('tally_seconds', 'runtime-by-voters-minutes', 'Tally runtime by number of voters', 'Tally wall time (minutes)', 60),
        ('peak_rss_gib', 'memory-by-voters', 'Peak memory by number of voters', 'Whole-process peak RSS (GiB)', 1)]:
        if args.only_minutes and divisor != 60:
            continue
        fig, ax = plt.subplots(figsize=(10.8, 6.6))
        ax.set_xscale('log'); ax.set_yscale('log')
        ax.axvspan(10000, 650000, color='#edf1f5', zorder=0)
        ax.axvline(10000, color='#95a2af', linewidth=1, linestyle=':')
        handles = []
        for (mode, label), color, marker in zip(LABELS.items(), COLORS, ['o', 's', '^', 'D']):
            data = sorted((p for p in points if p['strategy'] == mode), key=lambda p: p['n'])
            handles.append(Line2D([], [], color=color, marker=marker, label=label))
            for a, b in zip(data, data[1:]):
                style = '--' if (metric == 'tally_seconds' and b['n'] >= 10000) or (metric == 'peak_rss_gib' and mode.startswith('sequential')) else '-'
                ax.plot([a['n'], b['n']], [a[metric+'_median']/divisor, b[metric+'_median']/divisor], color=color, linestyle=style, linewidth=1.8)
            for p in data:
                y = p[metric+'_median']/divisor
                ax.errorbar(p['n'], y, yerr=[[y-p[metric+'_min']/divisor], [p[metric+'_max']/divisor-y]], color=color,
                            marker=marker, markersize=7 if mode.startswith('tree') else 5, capsize=3, linestyle='none',
                            markerfacecolor='white' if metric == 'tally_seconds' and p['n'] >= 10000 else color)
            if divisor == 60:
                for p in data:
                    if p['n'] != 500000:
                        continue
                    y = p[metric+'_median']/divisor
                    ax.hlines(y, 1800, 500000, color=color, linestyle=':', linewidth=1.2)
                    offset = 15 if mode == 'tree-none' else -20
                    ax.annotate(f'{label} at 500k: {y:.6f} min', xy=(2400, y),
                                xytext=(0, offset), textcoords='offset points',
                                color=color, fontsize=10,
                                bbox=dict(facecolor='white', edgecolor='none', alpha=.9, pad=2))
        ax.set_xlim(150, 650000)
        ax.set_xticks(counts)
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f'{v/1000:g}k' if v >= 1000 else str(int(v))))
        ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f'{v:g}'))
        ax.set_xlabel('Number of voters n (log scale)'); ax.set_ylabel(ylabel+' · log scale')
        ax.set_title(title, loc='left', fontsize=17, pad=18)
        ax.grid(axis='y', which='major', alpha=.2)
        ax.legend(handles=handles, loc='upper left', frameon=False, fontsize=10)
        ax.text(.99, 1.015, 'b = k = 5 · T = 5 · 3 parties', ha='right', transform=ax.transAxes, color='#56616c', fontsize=10)
        note = ('Filled points: measured five-period tally. Open points / dashed lines: five-period projection.\n'
                'Includes refresh; excludes client encryption, setup and final decryption.') if metric == 'tally_seconds' else (
                'Observed whole-process RAM, including setup and client preparation where present.\n'
                + ('Shaded region: fresh encrypted benchmark inputs; one input period.' if any(r['input_execution_mode'] == 'sampled-fresh-input-benchmark' for r in runs) else 'Shaded region: benchmark inputs (reused zero ciphertexts; one input period).'))
        fig.text(.10, .065, f'Median / min–max; {repetition_label} measured runs per point. Single runs have no spread; warm-ups excluded.\n'+note,
                 fontsize=9, color='#56616c', va='top')
        fig.subplots_adjust(left=.10, right=.97, bottom=.22, top=.87)
        for ext in ['png', 'svg', 'pdf']:
            fig.savefig(args.output / f'{filename}.{ext}', dpi=180)
        plt.close(fig)
    report = dict(measured_runs=len(runs), points=len(points), voter_counts=counts,
                  repetitions=sorted({p['repetitions'] for p in points}), skipped_campaigns=skipped,
                  hostname=runs[0]['hostname'], git_sha=runs[0]['git_sha'])
    if not args.only_minutes:
        (args.output / 'provenance.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
