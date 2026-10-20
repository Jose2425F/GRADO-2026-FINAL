import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from iniciar_estudio_kpi import remaining_budget

class StudyBudgetTests(unittest.TestCase):
    def test_access_check_is_charged_to_total_budget(self):
        value=remaining_budget({'status':'accepted','usage_complete':True,'cost_estimate_usd':0.004},20)
        self.assertEqual(value,19.996)
        self.assertLessEqual(value+0.004,20)
    def test_unknown_usage_and_rejection_never_start_study(self):
        for summary in [dict(status='accepted',usage_complete=False,cost_estimate_usd=0),dict(status='fallback',usage_complete=True,cost_estimate_usd=0),dict(status='accepted',usage_complete=True,cost_estimate_usd=None)]:
            with self.assertRaises(ValueError):remaining_budget(summary,20)
    def test_insufficient_reservation_never_starts_study(self):
        with self.assertRaises(ValueError):remaining_budget({'status':'accepted','usage_complete':True,'cost_estimate_usd':3},20)

if __name__=='__main__':unittest.main()
