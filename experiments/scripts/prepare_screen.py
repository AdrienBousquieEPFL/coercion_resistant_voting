#!/usr/bin/env python3
"""Copy the current source and add a compact, explicitly synthetic noise screen.

This executes the actual echo and downstream tally. Ingress is replaced with
fresh packed payload/shared-mask aggregates and amplified residual error. It is not
an independent-encryption full-electorate test or a runtime benchmark.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-root',type=Path,default=Path('/private/tmp'))
args=parser.parse_args()
project=Path(__file__).resolve().parents[2]
out=Path(tempfile.mkdtemp(prefix='voting-campaign-screen-',dir=args.output_root))
manifest={}
for source in list(project.glob('*.go'))+[project/'go.mod',project/'go.sum']:
    data=source.read_bytes();(out/source.name).write_bytes(data)
    manifest[source.name]=hashlib.sha256(data).hexdigest()
p=out/'main.go';s=p.read_text()
s=s.replace('periodAggregates := streamAndAggregatePeriodInputs(', 'periodAggregates := screenAndAggregatePeriodInputs(')
s=s.replace('addZeroSubmissionScenario(candidatePeriods, delegationPeriods, b, k)', 'screenWorkload(candidatePeriods,delegationPeriods,b,k)\n\t\taddZeroSubmissionScenario(candidatePeriods, delegationPeriods, b, k)')
s=s.replace('phSupport.Stop()', 'screenAmplifyResidual(ctDelegateSupport, screenCiphertextCount(layout))\n\tphSupport.Stop()')
s=s.replace('ctResultRows := ctAcc.CopyNew()', 'screenAmplifyResidual(ctAcc, screenCiphertextCount(layout))\n\tctResultRows := ctAcc.CopyNew()')
p.write_text(s)
(out/'screen.go').write_text((Path(__file__).parent/'screen.go.txt').read_text())
(out/'source_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(out)
