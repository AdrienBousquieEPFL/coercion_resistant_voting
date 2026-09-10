#!/usr/bin/env python3
"""Build a per-configuration parameter/cost table from exact Go-generated files."""
import argparse
import csv
import json
import math
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--screens',type=Path,nargs='+',default=[])
    args=parser.parse_args()
    with (ROOT/'experiments.csv').open() as f: rows=list(csv.DictReader(f))
    security={}
    for file in sorted((ROOT/'validation').glob('security*.json')):
        security.update({p['file']:p for p in json.loads(file.read_text())})
    if (ROOT/'parameter-security.json').exists():
        security.update({p['file']:p for p in json.loads((ROOT/'parameter-security.json').read_text())})
    screens={}
    for file in args.screens:
        with file.open() as f:
            for row in csv.DictReader(f):
                meta=Path(row['run_directory'])/'meta.json'
                row['tally_flow']=json.loads(meta.read_text()).get('tally_flow','pre-streaming') if meta.exists() else row.get('tally_flow','unknown')
                screens.setdefault(row['family'],[]).append(row)
    fields=['experiment_id','parameter_file','logN','logQ_bits','logP_bits','plaintext_modulus','Q_primes','P_primes','lattice_security_bits','voters_per_ciphertext','ciphertexts','refresh_boundaries','refresh_ciphertexts','ingestion_periods_measured','input_additions_measured_max','active_period_accumulator_ciphertexts','active_period_accumulator_coefficient_gib','total_period_accumulator_ciphertexts_created','synthetic_trials','synthetic_min_margin_bits','synthetic_status']
    with (ROOT/'parameter-table.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields,lineterminator="\n");writer.writeheader()
        for row in rows:
            file=ROOT/row['parameter_file'];p=json.loads(file.read_text())
            n,b,k,T=map(int,[row['n'],row['b'],row['k'],row['T']])
            ring_degree=2**p['logN'];V=2*((ring_degree//2)//max(b,k));C=(n+V-1)//V
            interval=int(row['refresh_interval'])
            intermediate=sum(p%interval==0 for p in range(1,T-1)) if row['refresh_mode']!='none' and row['echo_mode']=='sequential' and interval>0 else 0
            refresh_boundaries=0 if row['refresh_mode']=='none' else 1+intermediate
            refresh_ct=2*C*refresh_boundaries
            periods=1 if row['execution_mode']=='benchmark' else T
            family=f"{file.stem}-b{b}-k{k}-{row['strategy']}"
            evidence=screens.get(family,[])
            margins=[float(s['min_margin_bits']) for s in evidence if s['min_margin_bits']!='']
            status='not-screened'
            if evidence:
                flows={s['tally_flow'] for s in evidence}
                provenance='masked-echo-v3' if flows=={'period-streaming-masked-echo-v3'} else 'historical-flow'
                status=f'passed-{provenance}-synthetic-screen' if all(s['status']=='passed' for s in evidence) else 'failed-synthetic-screen'
            writer.writerow(dict(experiment_id=row['experiment_id'],parameter_file=row['parameter_file'],logN=p['logN'],logQ_bits=sum(math.log2(int(q)) for q in p['Q']),logP_bits=sum(math.log2(int(q)) for q in p['P']),plaintext_modulus=p['plaintext_modulus'],Q_primes=len(p['Q']),P_primes=len(p['P']),lattice_security_bits=security[file.name]['minimum_bits'],voters_per_ciphertext=V,ciphertexts=C,refresh_boundaries=refresh_boundaries,refresh_ciphertexts=refresh_ct,ingestion_periods_measured=periods,input_additions_measured_max=3*n*periods,active_period_accumulator_ciphertexts=3*C,active_period_accumulator_coefficient_gib=3*C*2*ring_degree*len(p['Q'])*8/2**30,total_period_accumulator_ciphertexts_created=3*T*C,synthetic_trials=len(evidence),synthetic_min_margin_bits=min(margins) if margins else '',synthetic_status=status))
    print(f'Wrote {ROOT/"parameter-table.csv"}')

if __name__=='__main__':main()
