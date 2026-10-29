"""
Test cases for Task 13 - SentinelLog
Run: python -m unittest test_log_analyzer.py -v
 or: python test_log_analyzer.py
"""

import os
import unittest
import tempfile
import csv

from log_analyzer import check_password_policy, analyze_logs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_LOG_PATH = os.path.join(BASE_DIR, "sample_logs.csv")


class TestPasswordPolicy(unittest.TestCase):

    def test_weak_common_password_fails(self):
        result = check_password_policy("password")
        self.assertFalse(result["compliant"])
        self.assertIn("Matches a common weak password list", result["reasons"])

    def test_too_short_password_fails(self):
        result = check_password_policy("Ab1!", min_length=10)
        self.assertFalse(result["compliant"])
        self.assertTrue(any("Too short" in r for r in result["reasons"]))

    def test_missing_special_char_fails(self):
        result = check_password_policy("AbcdefGh12", min_length=10)
        self.assertFalse(result["compliant"])
        self.assertIn("Missing special character", result["reasons"])

    def test_repeated_chars_fails(self):
        result = check_password_policy("Aaaa1111!!!!", min_length=10)
        self.assertFalse(result["compliant"])
        self.assertIn("Contains 3+ repeated characters in a row", result["reasons"])

    def test_strong_password_passes(self):
        result = check_password_policy("Str0ng&Pass2026", min_length=10)
        self.assertTrue(result["compliant"])
        self.assertEqual(result["reasons"], [])

    def test_missing_uppercase_fails(self):
        result = check_password_policy("lowercase1!", min_length=10)
        self.assertIn("Missing uppercase letter", result["reasons"])

    def test_missing_digit_fails(self):
        result = check_password_policy("NoDigitsHere!", min_length=10)
        self.assertIn("Missing digit", result["reasons"])


class TestLogAnalyzer(unittest.TestCase):

    def setUp(self):
        self.summary = analyze_logs(SAMPLE_LOG_PATH, brute_force_threshold=5)

    def test_total_events_counted(self):
        with open(SAMPLE_LOG_PATH, newline="", encoding="utf-8") as f:
            expected = sum(1 for _ in csv.DictReader(f))
        self.assertEqual(self.summary["total_events"], expected)

    def test_success_and_failure_sum_to_total(self):
        self.assertEqual(
            self.summary["total_successes"] + self.summary["total_failures"],
            self.summary["total_events"],
        )

    def test_brute_force_ip_flagged(self):
        # 203.0.113.77 has 11 failures in the sample log (6 for 'admin' + 5 for 'root)
        self.assertIn("203.0.113.77", self.summary["flagged_brute_force_ips"])
        self.assertGreaterEqual(self.summary["flagged_brute_force_ips"]["203.0.113.77"], 5)

    def test_low_volume_ip_not_flagged(self):
        # 198.51.100.23 only has 2 failures, below threshold of 5
        self.assertNotIn("198.51.100.23", self.summary["flagged_brute_force_ips"])

    def test_suspicious_account_detected(self):
        # bob has 3 consecutive failures then a success
        usernames_flagged = [a["username"] for a in self.summary["suspicious_accounts"]]
        self.assertIn("bob", usernames_flagged)

    def test_clean_account_not_flagged(self):
        # alice only ever succeeds, should never appear as suspicious
        usernames_flagged = [a["username"] for a in self.summary["suspicious_accounts"]]
        self.assertNotIn("alice", usernames_flagged)

    def test_unique_ip_and_user_counts_are_sane(self):
        self.assertGreater(self.summary["unique_ips"], 0)
        self.assertGreater(self.summary["unique_users"], 0)

    def test_malformed_csv_raises_cleanly(self):
        # Verify analyze_logs fails loudly (not silently) on a missing file
        with self.assertRaises(FileNotFoundError):
            analyze_logs(os.path.join(BASE_DIR, "does_not_exist.csv"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
