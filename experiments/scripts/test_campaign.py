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
 w=csv.writer(f);w.writerow(['phase','wall_ms','cpu_ms','multiparty_wall_ms','multiparty_cpu_ms']);w.writerow(['4.2-tally-periodic-echo-tree',2,1,0.5,0.25]);w.writerow(['4.2-tally-periodic-echo-tree',4,2,1.5,0.75])
with (run/'components.csv').open('w') as f:
 w=csv.writer(f);w.writerow(['component','wall_ms','cpu_ms','notes']);w.writerow(['4.1-server-aggregation',3,2,'measured']);w.writerow(['4.1-aggregate-initialization',5,4,'server']);w.writerow(['multiparty:refresh',2,1,'protocol']);w.writerow(['multiparty:threshold-decryption',7,6,'outside tally'])
print(f'[metrics] run_id=fake output={run}')
print('ASSERT PASSED: final tally')
'''

class CampaignMatrixTests(unittest.TestCase):
    def test_exact_requested_grid(self):
        counts={200:2,500:2,1000:2,5000:2,10000:4,25000:2,50000:4,100000:2,500000:2}
        with (ROOT/'experiments.csv').open() as f: rows=list(csv.DictReader(f))
        self.assertEqual(len(rows),22)
        self.assertEqual(len({r['experiment_id'] for r in rows}),22)
        self.assertEqual({int(r['n']) for r in rows},set(counts))
        for n,count in counts.items(): self.assertEqual(len(selected_rows(n)),count)
        for row in rows:
            self.assertEqual((int(row['b']),int(row['k'])),(5,5))
            if int(row['n']) not in [10000,50000]: self.assertIn(row['strategy'],['tree-none','sequential-none'])
            if row['strategy']=='sequential-none':
                self.assertEqual(row['echo_mode'],'sequential')
                self.assertEqual(row['refresh_mode'],'none')
                self.assertEqual(row['refresh_interval'],'0')
        for n in counts:
            self.assertEqual({r['strategy'] for r in selected_rows(n) if r['refresh_mode']=='none'},{'tree-none','sequential-none'})
            self.assertEqual(len({r['parameter_file'] for r in selected_rows(n) if r['refresh_mode']=='none'}),2)
        for row in rows:
            self.assertTrue((ROOT/row['parameter_file']).is_file())
            profile=json.loads((ROOT/row['parameter_file']).read_text())
            self.assertGreater(profile['plaintext_modulus'],int(row['n'])*int(row['qmax']))
            self.assertEqual(profile['logN'],15 if row['refresh_mode']=='none' else 14)

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

    def test_only_final_refresh_for_both_modes(self):
        for n in [10000,50000]:
            refreshed=[r for r in selected_rows(n) if r['refresh_mode']=='collective']
            self.assertEqual(len(refreshed),2)
            self.assertEqual({r['strategy'] for r in refreshed},{'tree-final','sequential-final'})
            for row in refreshed:
                interval=int(row['refresh_interval'])
                self.assertEqual(interval,5 if row['echo_mode']=='sequential' else 0)
                if interval:
                    self.assertFalse(any(p%interval==0 for p in range(1,int(row['T'])-1)))

    def test_runner_preserves_runs_and_excludes_warmups(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/'fake runner.py';binary.write_text(FAKE_RUNNER);binary.chmod(0o755)
            output=root/'results'
            command=[sys.executable,str(ROOT/'scripts'/'run_campaign.py'),'--n=200','--shape=5,5','--strategy=tree-none','--binary',str(binary),'--output-root',str(output),'--warmups=1','--repeats=2']
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
                echo=next(r for r in summary if r['metric']=='phase:4.2-tally-periodic-echo-tree:wall_ms')
                self.assertEqual(int(echo['samples']),2)
                self.assertEqual(float(echo['median']),6)
                server=next(r for r in summary if r['metric']=='server_observed_wall_ms:five_input_periods')
                self.assertEqual(float(server['median']),12)
                mp=next(r for r in summary if r['metric']=='multiparty_tally_wall_ms')
                self.assertEqual(float(mp['median']),2)
                tally=next(r for r in summary if r['metric']=='tally_observed_wall_ms:five_input_periods')
                self.assertEqual(float(tally['median']),14)

    def test_legacy_summary_does_not_claim_separated_server_time(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/'fake';binary.write_text(FAKE_RUNNER);binary.chmod(0o755)
            output=root/'results'
            subprocess.run([sys.executable,str(ROOT/'scripts'/'run_campaign.py'),'--n=200','--shape=5,5','--strategy=tree-none','--binary',str(binary),'--output-root',str(output),'--repeats=1'],check=True,capture_output=True)
            campaign=next(output.iterdir())
            for phase in campaign.glob('raw/*/phases.csv'):
                with phase.open() as f: rows=list(csv.DictReader(f))
                with phase.open('w') as f:
                    w=csv.DictWriter(f,fieldnames=['phase','wall_ms','cpu_ms'],extrasaction='ignore');w.writeheader();w.writerows(rows)
            subprocess.run([sys.executable,str(ROOT/'scripts'/'summarize.py'),str(campaign)],check=True,capture_output=True)
            with (campaign/'measurements-summary.csv').open() as f: metrics=[r['metric'] for r in csv.DictReader(f)]
            self.assertFalse(any(m.startswith(('server_observed','tally_observed')) for m in metrics))
            self.assertTrue(any(m.startswith('legacy_server_inclusive_multiparty') for m in metrics))

    def test_timeout_is_recorded_before_stopping(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/'sleeper';binary.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(10)\n');binary.chmod(0o755)
            output=root/'results'
            result=subprocess.run([sys.executable,str(ROOT/'scripts'/'run_campaign.py'),'--n=200','--shape=5,5','--strategy=tree-none','--binary',str(binary),'--output-root',str(output),'--timeout=0.1'],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            campaign=next(output.iterdir())
            with (campaign/'executions.csv').open() as f:runs=list(csv.DictReader(f))
            self.assertEqual(len(runs),1)
            self.assertEqual(runs[0]['status'],'timeout')
            self.assertTrue(Path(runs[0]['log']).exists())

if __name__=='__main__':unittest.main()
