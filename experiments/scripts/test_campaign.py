import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from run_campaign import ROOT,command_for,selected_rows

FAKE_RUNNER=r'''#!/usr/bin/env python3
import csv,json,sys,tempfile
from pathlib import Path
args=dict(s[2:].split('=',1) for s in sys.argv[1:] if s.startswith('--') and '=' in s)
out=Path(args['output-root']);out.mkdir(parents=True,exist_ok=True)
run=Path(tempfile.mkdtemp(dir=out))
seed=args['workload-seed']
peak=1000 if 'warmup' in seed else 10+int(seed.rsplit('-',1)[-1])
(run/'meta.json').write_text(json.dumps({'parameter_id':'fake-parameter'}))
(run/'summary.json').write_text(json.dumps({'process_peak_rss_mib':peak}))
with (run/'phases.csv').open('w') as f:
 w=csv.writer(f);w.writerow(['phase','wall_ms','cpu_ms']);w.writerow(['4.2-tally-periodic-echo-tree',2,1])
with (run/'components.csv').open('w') as f:
 w=csv.writer(f);w.writerow(['component','wall_ms','cpu_ms','notes']);w.writerow(['4.1-server-validity-gating-and-aggregation',3,2,'measured'])
print(f'[metrics] run_id=fake output={run}')
print('ASSERT PASSED: final tally')
'''

class CampaignMatrixTests(unittest.TestCase):
    def test_exact_requested_grid(self):
        counts={200:5,500:5,1000:5,5000:5,10000:20,25000:5,50000:20,100000:5,500000:5}
        with (ROOT/'experiments.csv').open() as f: rows=list(csv.DictReader(f))
        self.assertEqual(len(rows),75)
        self.assertEqual(len({r['experiment_id'] for r in rows}),75)
        self.assertEqual({int(r['n']) for r in rows},set(counts))
        for n,count in counts.items(): self.assertEqual(len(selected_rows(n)),count)
        for row in rows:
            self.assertIn((int(row['b']),int(row['k'])),[(5,5),(20,20),(100,100),(100,5),(5,100)])
            if int(row['n']) not in [10000,50000]: self.assertEqual(row['strategy'],'tree-none')
            self.assertTrue((ROOT/row['parameter_file']).is_file())

    def test_benchmark_has_one_full_input_period_and_five_echo_periods(self):
        for n in [200,5000,10000,25000,50000,500000]:
            for row in selected_rows(n):
                command=command_for(row,Path('/tmp/executable'),Path('/tmp/results'),'seed')
                self.assertIn('--T=5',command)
                self.assertIn('--diagnostic-checks=final',command)
                self.assertNotIn('--noise-check',command)
                self.assertEqual('benchmark' in command,n>=10000)
                if n>=10000:self.assertIn(f'--sample-voters={n}',command)
                else:self.assertFalse(any(c.startswith('--sample-voters=') for c in command))

    def test_sequential_intervals_only_two_and_three(self):
        for n in [10000,50000]:
            sequential=[r for r in selected_rows(n) if r['echo_mode']=='sequential']
            self.assertEqual(len(sequential),10)
            self.assertEqual({r['refresh_interval'] for r in sequential},{'2','3'})
            self.assertTrue(all(r['refresh_mode']=='collective' for r in sequential))

    def test_runner_preserves_runs_and_excludes_warmups(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/'fake runner.py';binary.write_text(FAKE_RUNNER);binary.chmod(0o755)
            output=root/'results'
            command=[sys.executable,str(ROOT/'scripts'/'run_campaign.py'),'--n=200','--shape=5,5','--binary',str(binary),'--output-root',str(output),'--warmups=1','--repeats=2']
            for _ in range(2):subprocess.run(command,check=True,capture_output=True,text=True)
            campaigns=list(output.iterdir());self.assertEqual(len(campaigns),2)
            for campaign in campaigns:
                with (campaign/'executions.csv').open() as f:runs=list(csv.DictReader(f))
                self.assertEqual(len(runs),3)
                self.assertEqual(len({r['run_directory'] for r in runs}),3)
                self.assertTrue(all(r['status']=='passed' for r in runs))
                with (campaign/'measurements-summary.csv').open() as f:summary=list(csv.DictReader(f))
                peak=next(r for r in summary if r['metric']=='process_peak_rss_mib')
                self.assertEqual(int(peak['samples']),2)
                self.assertEqual(float(peak['median']),10.5)

    def test_timeout_is_recorded_before_stopping(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/'sleeper';binary.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(10)\n');binary.chmod(0o755)
            output=root/'results'
            result=subprocess.run([sys.executable,str(ROOT/'scripts'/'run_campaign.py'),'--n=200','--shape=5,5','--binary',str(binary),'--output-root',str(output),'--timeout=0.1'],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            campaign=next(output.iterdir())
            with (campaign/'executions.csv').open() as f:runs=list(csv.DictReader(f))
            self.assertEqual(len(runs),1)
            self.assertEqual(runs[0]['status'],'timeout')
            self.assertTrue(Path(runs[0]['log']).exists())

if __name__=='__main__':unittest.main()
