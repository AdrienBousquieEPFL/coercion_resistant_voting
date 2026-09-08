#!/usr/bin/env python3
"""Summarize measured executions only; keep projections explicitly separate."""
import csv
from collections import defaultdict
import json
from pathlib import Path
import statistics
import sys

root=Path(sys.argv[1]).resolve()
with (root/'executions.csv').open() as f:
    runs=list(csv.DictReader(f))
values=defaultdict(list)
for run in runs:
    if run['run_kind']!='measured' or run['status']!='passed': continue
    directory=Path(run['run_directory'])
    key=(run['experiment_id'],run['parameter_id'])
    values[key+('process_peak_rss_mib',)].append(float(run['process_peak_rss_mib']))
    per_run=defaultdict(float)
    downstream_wall=0.0
    multiparty_tally_wall=0.0
    separated=True
    initialization_wall=None
    ingestion_wall=None
    projected_ingestion_wall=None
    # Components distinguish measured one-period ingestion from any five-period
    # projection. Never combine these rows or present projections as measured.
    for filename,label in [('phases.csv','phase'),('components.csv','component')]:
        with (directory/filename).open() as f:
            for row in csv.DictReader(f):
                name=row.get('name') or row.get('phase') or row.get('component')
                if name is None: raise ValueError(f'Unknown schema in {directory/filename}')
                if label=='phase' and any(name.startswith(f'4.{i}-') for i in range(2,8)):
                    downstream_wall+=float(row['wall_ms'])
                    if 'multiparty_wall_ms' not in row: separated=False
                    else: multiparty_tally_wall+=float(row['multiparty_wall_ms'])
                if label=='component' and name=='4.1-aggregate-initialization':
                    initialization_wall=float(row['wall_ms'])
                if label=='component' and name in ('4.1-server-aggregation','4.1-server-validity-gating-and-aggregation'):
                    ingestion_wall=float(row['wall_ms'])
                if label=='component' and 'estimated' in name:
                    projected_ingestion_wall=float(row['wall_ms'])
                for metric in ['wall_ms','cpu_ms','multiparty_wall_ms','multiparty_cpu_ms']:
                    if metric in row:
                        per_run[f'{label}:{name}:{metric}']+=float(row[metric])
    for metric,value in per_run.items():
        values[key+(metric,)].append(value)
    if separated and initialization_wall is not None:
        server_downstream=max(0.0,downstream_wall-multiparty_tally_wall)
        values[key+('multiparty_tally_wall_ms',)].append(multiparty_tally_wall)
        refresh_wall=per_run.get('component:multiparty:refresh:wall_ms',0.0)
        values[key+('tally_refresh_wall_ms',)].append(refresh_wall)
        if ingestion_wall is not None:
            scope='one_input_period' if run['execution_mode']=='benchmark' else 'five_input_periods'
            server_wall=initialization_wall+ingestion_wall+server_downstream
            values[key+(f'server_observed_wall_ms:{scope}',)].append(server_wall)
            values[key+(f'tally_observed_wall_ms:{scope}',)].append(server_wall+refresh_wall)
        if projected_ingestion_wall is not None:
            server_projected=initialization_wall+projected_ingestion_wall+server_downstream
            values[key+('server_projected_wall_ms:five_input_periods',)].append(server_projected)
            values[key+('tally_projected_wall_ms:five_input_periods',)].append(server_projected+refresh_wall)
    else:
        # Historical runs cannot retrospectively separate embedded protocols.
        if ingestion_wall is not None:
            scope='one_input_period' if run['execution_mode']=='benchmark' else 'five_input_periods'
            values[key+(f'legacy_server_inclusive_multiparty_excluding_initialization_wall_ms:{scope}',)].append(ingestion_wall+downstream_wall)
        if projected_ingestion_wall is not None:
            values[key+('legacy_server_inclusive_multiparty_excluding_initialization_projected_wall_ms:five_input_periods',)].append(projected_ingestion_wall+downstream_wall)

with (root/'measurements-summary.csv').open('w',newline='') as f:
    writer=csv.writer(f);writer.writerow(['experiment_id','parameter_id','metric','samples','median','min','max'])
    for (experiment,parameter,metric),samples in sorted(values.items()):
        writer.writerow([experiment,parameter,metric,len(samples),statistics.median(samples),min(samples),max(samples)])
print(f'Wrote {root/"measurements-summary.csv"}')
