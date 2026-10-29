"""
Test cases for Task 07 - SecureScope
Run: python -m unittest test_risk_assessment.py -v
 or: python test_risk_assessment.py
"""

import os
import unittest

from threat_model import load_application, generate_threats, summarize_assets, summarize_trust_boundaries

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
THREATS_JSON = os.path.join(BASE_DIR, "threats.json")


class TestThreatModel(unittest.TestCase):

    def setUp(self):
        self.app_data = load_application(THREATS_JSON)
        self.threats = generate_threats(self.app_data)
        self.assets = summarize_assets(self.app_data)
        self.boundaries = summarize_trust_boundaries(self.app_data)

    def test_application_loads(self):
        self.assertEqual(self.app_data["application"]["name"], "QuickCart")

    def test_threats_generated(self):
        self.assertGreater(len(self.threats), 0)

    def test_threats_sorted_by_severity(self):
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        ranks = [severity_order[t["risk_rating"]] for t in self.threats]
        self.assertEqual(ranks, sorted(ranks))

    def test_every_threat_has_mitigation(self):
        for t in self.threats:
            self.assertTrue(t["mitigation"])
            self.assertGreater(len(t["mitigation"]), 10)

    def test_every_threat_has_valid_stride_category(self):
        valid = {"Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                 "Denial of Service", "Elevation of Privilege"}
        for t in self.threats:
            self.assertIn(t["stride_category"], valid)

    def test_payment_flow_flags_information_disclosure(self):
        payment_threats = [t for t in self.threats if "Payment" in t["flow_description"]]
        categories = [t["stride_category"] for t in payment_threats]
        self.assertIn("Information Disclosure", categories)

    def test_admin_flow_flags_elevation_of_privilege(self):
        admin_threats = [t for t in self.threats if "Admin" in t["flow_description"]]
        categories = [t["stride_category"] for t in admin_threats]
        self.assertIn("Elevation of Privilege", categories)

    def test_assets_sorted_by_sensitivity(self):
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        ranks = [order[a["sensitivity"]] for a in self.assets]
        self.assertEqual(ranks, sorted(ranks))

    def test_critical_asset_present(self):
        names = [a["name"] for a in self.assets if a["sensitivity"] == "Critical"]
        self.assertTrue(any("Payment" in n for n in names))

    def test_trust_boundaries_loaded(self):
        self.assertEqual(len(self.boundaries), 4)

    def test_internal_only_flow_not_in_threats(self):
        # web_app -> auth_service does not cross a trust boundary (internal call)
        flow_ids = [t["flow"] for t in self.threats]
        self.assertNotIn("web_app->auth_service", flow_ids)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_application(os.path.join(BASE_DIR, "does_not_exist.json"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
