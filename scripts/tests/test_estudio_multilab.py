import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tesis.estudio_multilab import analyze,draft


class MultiLabTests(unittest.TestCase):
    def row(self,lab,arm,pair=1,**extra):
        return {'lab_id':lab,'architecture':arm,'pair':pair,'status':'complete','expected_tasks':25,'tasks_valid':25,
                'seconds':100 if arm=='single' else 80,'TP':4,'FN':0,'known_tokens':1000 if arm=='single' else 800,
                'usage_complete':True,'configuration_sha256':lab,'reference_sha256':lab,'model':'test','token_budget':60000,**extra}
    def test_proposed_design_is_balanced_per_lab_and_not_executed(self):
        d=draft();self.assertEqual(d['formal_runs'],60);self.assertEqual(d['formal_pairs'],30)
        self.assertEqual(len(d['labs']),5);self.assertEqual(d,draft())
        for lab in d['labs']:
            pairs=[p for p in d['order'] if p['lab_id']==lab['id']]
            self.assertEqual(len(pairs),6);self.assertEqual(sum(p['order'][0]=='single' for p in pairs),3)
    def test_same_pair_number_in_different_labs_never_pairs_across_labs(self):
        result=analyze([self.row('A','single'),self.row('B','multiagent')])
        self.assertEqual(result['pairs'],[]);self.assertEqual(result['attempts'],2)
        result=analyze([self.row('A','single'),self.row('A','multiagent',reference_sha256='foreign')])
        self.assertEqual(result['pairs'],[])
    def test_macro_weights_labs_equally_and_preserves_unfavorable_results(self):
        rows=[self.row('A','single'),self.row('A','multiagent')]
        for pair in range(1,4):rows.extend([self.row('B','single',pair),self.row('B','multiagent',pair,seconds=120)])
        result=analyze(rows);self.assertEqual(result['macro_metrics']['TRTO_percent']['mean_of_lab_means'],0)
        self.assertLess(result['by_lab']['B']['metrics']['TRTO_percent']['mean'],0)
    def test_failed_attempt_retains_detection_and_has_no_fast_time_or_unknown_token_efficiency(self):
        result=analyze([self.row('A','single'),self.row('A','multiagent',status='partial',seconds=1,TP=0,FN=4,usage_complete=False)])
        pair=result['pairs'][0];self.assertEqual(pair['IDE_percent'],-100)
        self.assertNotIn('TRTO_percent',pair);self.assertNotIn('ETV_ratio',pair)
    def test_duplicate_attempts_are_retained_and_not_selected_by_best_result(self):
        rows=[self.row('A','single'),self.row('A','multiagent'),self.row('A','multiagent',seconds=1)]
        r=analyze(rows);self.assertEqual(r['attempts'],3);self.assertEqual(r['pairs'],[])
