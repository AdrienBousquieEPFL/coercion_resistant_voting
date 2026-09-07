#!/usr/bin/env python3
"""Screen parameter families using the separate synthetic diagnostic binary."""
import argparse
import csv
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

from run_campaign import ROOT,PROJECT,stop_process

def families():
    grouped={}
    with (ROOT/'experiments.csv').open() as f:
        for row in csv.DictReader(f):
            key=(row['parameter_file'],row['b'],row['k'],row['strategy'])
            if key not in grouped or int(row['n'])>int(grouped[key]['n']): grouped[key]=row
    return list(grouped.values())

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    parser.add_argument('--repeats',type=int,default=20)
    parser.add_argument('--output-root',type=Path,default=ROOT/'validation')
    parser.add_argument('--strategy',action='append',default=[])
    parser.add_argument('--shape',action='append',default=[])
    parser.add_argument('--parameter-file',type=Path,help='candidate override for parameter search; does not change the experiment matrix')
    parser.add_argument('--timeout',type=float,default=1800)
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args()
    if args.repeats<1 or args.timeout<=0: parser.error('repeats and timeout must be positive')
    cases=[r for r in families() if (not args.strategy or r['strategy'] in args.strategy) and (not args.shape or f"{r['b']},{r['k']}" in args.shape)]
    if args.parameter_file:
        candidate=args.parameter_file.resolve()
        for row in cases:row['parameter_file']=str(candidate.relative_to(ROOT))
    if not cases: parser.error('no matching parameter families')
    if args.dry_run:
        print(json.dumps(cases,indent=2));return
    args.output_root.mkdir(parents=True,exist_ok=True)
    output=Path(tempfile.mkdtemp(prefix='screen-',dir=args.output_root.resolve()))
    (output/'cases.json').write_text(json.dumps(cases,indent=2)+'\n')
    print(output,flush=True)
    fields=['family','repetition','workload','probe_n','target_n','status','exit_code','min_margin_bits','elapsed_seconds','run_directory','log']
    failures=0
    with (output/'screens.csv').open('x',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader();f.flush()
        for row in cases:
            family=f"{Path(row['parameter_file']).stem}-b{row['b']}-k{row['k']}-{row['strategy']}"
            for repetition in range(args.repeats):
                pattern=['concentrated','balanced','random'][repetition%3]
                probe_n=max(6,int(row['k'])+1)
                log=output/f'{family}-{repetition}.log'
                command=[str(args.binary.resolve()),f'--n={probe_n}',f"--b={row['b']}",f"--k={row['k']}",'--T=5','--N=3','--qmax=1',f"--echo-mode={row['echo_mode']}",f"--refresh-mode={row['refresh_mode']}",f"--echo-refresh-interval={row['refresh_interval']}",f"--parameter-file={ROOT/row['parameter_file']}",f"--screen-target-n={row['n']}",f'--screen-workload={pattern}',f'--workload-seed=screen-{repetition}',f'--output-root={output/"raw"}','--noise-check','--noise-margin-min=20','--progress=false']
                (output/f'{family}-{repetition}.command.json').write_text(json.dumps(command,indent=2)+'\n')
                start=time.monotonic();status='passed'
                with log.open('x') as stream:
                    process=subprocess.Popen(command,cwd=PROJECT,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
                    try: code=process.wait(timeout=args.timeout)
                    except subprocess.TimeoutExpired:
                        stop_process(process);code=process.returncode;status='timeout'
                    except KeyboardInterrupt:
                        stop_process(process);raise
                if code and status=='passed':status='failed'
                text=log.read_text(errors='replace')
                match=re.search(r'^\[metrics\] run_id=.* output=(.+)$',text,re.MULTILINE)
                directory=Path(match.group(1)) if match else None
                margins=[]
                if directory and (directory/'noise.csv').exists():
                    with (directory/'noise.csv').open() as noise:
                        margins=[float(r['margin_bits']) for r in csv.DictReader(noise)]
                if status=='passed' and ('ASSERT PASSED: final tally' not in text or not margins): status='incomplete'
                record=dict(family=family,repetition=repetition,workload=pattern,probe_n=probe_n,target_n=row['n'],status=status,exit_code=code,min_margin_bits=min(margins) if margins else '',elapsed_seconds=time.monotonic()-start,run_directory=directory or '',log=log)
                writer.writerow(record);f.flush();print(json.dumps(record,default=str),flush=True)
                if status!='passed':
                    failures+=1;break # stop this parameter family, retain other independent screens
    if failures:raise SystemExit(f'{failures} parameter families failed; see {output/"screens.csv"}')

if __name__=='__main__':main()
