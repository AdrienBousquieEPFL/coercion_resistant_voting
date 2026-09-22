import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class RevisedCampaignTests(unittest.TestCase):
    def test_revised_commands(self):
        for n, name, count in [('1M', 'b3-k5-revised', 1), ('100k', 'b3-k100-revised', 2), ('500k', 'b3-k100-revised', 2)]:
            output = subprocess.check_output([sys.executable, str(ROOT / 'scripts/run_campaign.py'), '--n', n, '--set', name, '--dry-run'], text=True)
            rows = [json.loads(line) for line in output.splitlines()]
            self.assertEqual(len(rows), count)
            for row in rows:
                self.assertEqual((row['warmups'], row['repetitions']), (1, 1))
                cmd = row['command']
                path = Path(next(x.split('=', 1)[1] for x in cmd if x.startswith('--parameter-file=')))
                p = json.loads(path.read_text())
                self.assertTrue(path.is_file())
                self.assertEqual(p['plaintext_modulus'], 1179649 if name == 'b3-k5-revised' else 786433)
                refresh = '--refresh-mode=collective' in cmd
                self.assertEqual(p['logN'], 14 if refresh else 15)
                self.assertEqual(len(p['Q']), 6 if refresh else (9 if name == 'b3-k5-revised' else 8))
                self.assertIn('--diagnostic-checks=final', cmd)
                self.assertTrue(any(x.startswith('--output-root=') and x.endswith('/' + name) for x in cmd))

    def test_no_unrequested_configurations(self):
        p = subprocess.run([sys.executable, str(ROOT / 'scripts/run_campaign.py'), '--n', '50k', '--set', 'b3-k100-revised', '--dry-run'], capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('no configurations', p.stderr)
