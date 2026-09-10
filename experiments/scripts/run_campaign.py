#!/usr/bin/env python3
"""Execute one voter-count slice, with separate warm-ups and fresh processes."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
PROJECT=ROOT.parent

def create_campaign_directory(root, n):
    """Create a timestamped v2 campaign without reusing an existing directory."""
    name=f'n{n}-v2-{datetime.now(timezone.utc):%Y%m%d_%H%M%SZ}'
    suffix=1
    while True:
        directory=root/(name if suffix==1 else f'{name}-{suffix}')
        try:
            directory.mkdir()
            return directory
        except FileExistsError:
            suffix+=1

def selected_rows(n, strategies=(), shapes=()):
    with (ROOT/'experiments.csv').open() as f:
        rows=[r for r in csv.DictReader(f) if int(r['n'])==n]
    return [r for r in rows if (not strategies or r['strategy'] in strategies) and (not shapes or f"{r['b']},{r['k']}" in shapes)]

def command_for(row, binary, output, seed):
    command=[str(binary)]
    if row['execution_mode']=='benchmark':
        command+=['benchmark',f"--sample-voters={row['n']}"]
    command += [f"--n={row['n']}",f"--b={row['b']}",f"--k={row['k']}",f"--T={row['T']}",f"--qmax={row['qmax']}",f"--N={row['parties']}",f"--echo-mode={row['echo_mode']}",f"--refresh-mode={row['refresh_mode']}",f"--echo-refresh-interval={row['refresh_interval']}",f"--parameter-file={ROOT/row['parameter_file']}",f'--workload-seed={seed}',f'--output-root={output}','--diagnostic-checks=final','--metrics-sample-interval=1s','--progress=false']
    return command

def stop_process(process):
    if process.poll() is None:
        os.killpg(process.pid,signal.SIGTERM)
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL); process.wait()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--n',required=True,type=int)
    parser.add_argument('--binary',type=Path,default=PROJECT/'bin'/'voting-experiments')
    parser.add_argument('--output-root',type=Path,default=ROOT/'results')
    parser.add_argument('--warmups',type=int,default=1)
    parser.add_argument('--repeats',type=int,default=None,help='measured runs per configuration; default 1 for n>=10000, otherwise 3')
    parser.add_argument('--timeout',type=float,default=0,help='seconds per process; default 0 has no time limit, use 1800 for a 30-minute screening cap')
    parser.add_argument('--strategy',action='append',default=[])
    parser.add_argument('--shape',action='append',default=[],help='b,k; may be repeated')
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args()
    if args.repeats is None:
        args.repeats=1 if args.n>=10000 else 3
    if args.warmups<1 or args.repeats<1 or args.timeout<0: parser.error('use at least one warm-up and one repetition; timeout must be nonnegative')
    rows=selected_rows(args.n,args.strategy,args.shape)
    if not rows: parser.error('no configurations match the filters')
    binary=args.binary.resolve()
    for row in rows:
        if not row['parameter_file'] or not (ROOT/row['parameter_file']).is_file(): parser.error(f"missing concrete parameters for {row['experiment_id']}")
        expected='benchmark' if int(row['n'])>=10000 else 'fresh'
        if row['execution_mode']!=expected or (expected=='benchmark' and int(row['sample_voters'])!=int(row['n'])):
            parser.error(f"matrix ingestion scope mismatch: {row['experiment_id']}")
    if args.dry_run:
        for row in rows:
            seed=f"v1-n{row['n']}-b{row['b']}-k{row['k']}-measured-0"
            print(json.dumps(dict(experiment=row['experiment_id'],warmups=args.warmups,repetitions=args.repeats,command=command_for(row,binary,args.output_root.resolve(),seed))))
        return
    if not binary.is_file(): parser.error(f'build the executable first with scripts/build.sh; missing {binary}')
    args.output_root.mkdir(parents=True,exist_ok=True)
    campaign=create_campaign_directory(args.output_root.resolve(),args.n)
    (campaign/'logs').mkdir()
    manifest=dict(n=args.n,warmups=args.warmups,repeats=args.repeats,timeout_seconds=args.timeout,binary=str(binary),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),encryption_randomness='fresh-unseeded',configurations=rows)
    (campaign/'campaign.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(f'Campaign output: {campaign}',flush=True)
    fields=['experiment_id','strategy','execution_mode','run_kind','repetition','status','exit_code','elapsed_seconds','run_directory','log','parameter_id','workload_seed','process_peak_rss_mib']
    with (campaign/'executions.csv').open('x',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader();f.flush()
        for row in rows:
            for kind,count in [('warmup',args.warmups),('measured',args.repeats)]:
                for repetition in range(count):
                    seed=f"v1-n{row['n']}-b{row['b']}-k{row['k']}-{kind}-{repetition}"
                    log=campaign/'logs'/f"{row['experiment_id']}-{kind}-{repetition}.log"
                    command=command_for(row,binary,campaign/'raw',seed)
                    status='passed';start=time.monotonic();interrupted=False
                    with log.open('x') as output:
                        process=subprocess.Popen(command,cwd=PROJECT,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
                        try: code=process.wait(timeout=args.timeout or None)
                        except subprocess.TimeoutExpired:
                            status='timeout';stop_process(process);code=process.returncode
                        except KeyboardInterrupt:
                            status='interrupted';interrupted=True;stop_process(process);code=process.returncode
                    if code and status=='passed': status='failed'
                    text=log.read_text(errors='replace')
                    match=re.search(r'^\[metrics\] run_id=.* output=(.+)$',text,re.MULTILINE)
                    run_dir=Path(match.group(1)) if match else None
                    meta={};summary={}
                    if run_dir:
                        for name, destination in [('meta.json',meta),('summary.json',summary)]:
                            path=run_dir/name
                            if path.exists():
                                try: destination.update(json.loads(path.read_text()))
                                except (OSError,json.JSONDecodeError):
                                    if status=='passed':status='incomplete'
                    if status=='passed' and (not summary or 'ASSERT PASSED: final tally' not in text): status='incomplete'
                    record=dict(experiment_id=row['experiment_id'],strategy=row['strategy'],execution_mode=row['execution_mode'],run_kind=kind,repetition=repetition,status=status,exit_code=code,elapsed_seconds=time.monotonic()-start,run_directory=str(run_dir or ''),log=str(log),parameter_id=meta.get('parameter_id',''),workload_seed=seed,process_peak_rss_mib=summary.get('process_peak_rss_mib',''))
                    writer.writerow(record);f.flush()
                    print(f"{row['experiment_id']} {kind} {repetition}: {status}",flush=True)
                    if status!='passed':
                        raise SystemExit(130 if interrupted else f'Campaign stopped; inspect {log}')
    subprocess.run([os.environ.get('PYTHON','python3'),str(ROOT/'scripts'/'summarize.py'),str(campaign)],check=True)

if __name__=='__main__': main()
