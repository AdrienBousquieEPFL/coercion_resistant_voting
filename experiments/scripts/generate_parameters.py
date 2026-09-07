#!/usr/bin/env python3
"""Resolve campaign parameter files through the pinned Go/Lattigo executable."""
import argparse
import csv
import json
from pathlib import Path
import subprocess

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True,type=Path)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    matrix=root/'experiments.csv'
    with matrix.open() as f:
        reader=csv.DictReader(f); fields=reader.fieldnames; rows=list(reader)
    for row in rows:
        profile='tree-none-15' if row['strategy']=='tree-none' else 'refresh-14'
        command=[str(args.binary.resolve()),'--describe-parameters',f"--n={row['n']}",f'--parameter-profile={profile}']
        concrete=json.loads(subprocess.check_output(command,text=True))
        path=root/'parameters'/f"{profile}-t{concrete['plaintext_modulus']}.json"
        content=json.dumps(concrete,indent=2)+'\n'
        if path.exists():
            if json.loads(path.read_text())!=concrete:
                raise RuntimeError(f'Refusing to change existing concrete parameters: {path}')
        else:
            path.write_text(content)
        row['parameter_file']=str(path.relative_to(root))
    with matrix.open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields); writer.writeheader(); writer.writerows(rows)
    print(f'Resolved parameters for {len(rows)} configurations.')

if __name__=='__main__': main()
