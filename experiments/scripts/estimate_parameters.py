"""Run with SageMath; the estimator checkout must already be available."""
import argparse
import json
import math
from pathlib import Path
import subprocess
import sys

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--estimator',required=True,type=Path)
parser.add_argument('--output',required=True,type=Path)
parser.add_argument('parameters',nargs='+',type=Path)
args=parser.parse_args()
sys.path.insert(0,str(args.estimator.resolve()))
from sage.all import ZZ,log
from estimator import LWE,ND
from estimator.reduction import RC

revision=subprocess.check_output(['git','-C',str(args.estimator),'rev-parse','HEAD'],text=True).strip()
results=[]
for file in args.parameters:
    p=json.loads(file.read_text())
    modulus=ZZ(math.prod(int(q) for q in p['Q']+p['P']))
    params=LWE.Parameters(n=2**p['logN'],q=modulus,Xs=ND.Uniform(-1,1),Xe=ND.DiscreteGaussian(3.2))
    costs=LWE.estimate.rough(params,catch_exceptions=False)
    costs['classic_dual']=LWE.dual(params,red_cost_model=RC.ADPS16)
    bits={name:float(log(cost['rop'],2)) for name,cost in costs.items()}
    result=dict(file=file.name,estimator_revision=revision,cost_model='classical ADPS16 core-SVP',secret='uniform ternary (one remaining unknown share)',error_sigma=3.2,samples='unlimited',modulus=str(modulus),logN=p['logN'],attack_bits=bits,minimum_bits=min(bits.values()),target_bits=128,passes=min(bits.values())>=128)
    results.append(result)
    print(json.dumps(result),flush=True)
with args.output.open('x') as f:
    json.dump(results,f,indent=2);f.write('\n')
if not all(r['passes'] for r in results): raise SystemExit('A parameter profile failed the 128-bit lattice-security screen')
