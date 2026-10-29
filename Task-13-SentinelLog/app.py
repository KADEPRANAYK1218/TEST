"""
SentinelLog - Entry Point (Task 13 only)
Run: python app.py

This is the ONLY entry point for Task 13. Running this file produces
Task-13 output exclusively (password-policy check + log summary + a
CSV flagged-IPs export). It does not touch Task 07's files at all.
"""

import os
import csv
from log_analyzer import (
    check_password_file,
    analyze_logs,
    format_report,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_LOG_PATH = os.path.join(BASE_DIR, "sample_logs.csv")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")

# Synthetic passwords only - not real credentials, used to demo the checker.
SAMPLE_PASSWORDS = [
    "password",
    "Str0ng&Pass2026",
    "qwerty123",
    "C0rrect-Horse-Battery",
    "aaaAAA111!!!",
    "Tr0ub4dor&3!",
    "12345678",
]


def run_password_policy_demo():
    print("\n" + "=" * 60)
    print("SentinelLog - Password Policy Compliance Check")
    print("=" * 60)
    results = check_password_file(SAMPLE_PASSWORDS, min_length=10)
    compliant_count = sum(1 for r in results if r["compliant"])
    for r in results:
        verdict = "PASS" if r["compliant"] else "FAIL"
        print(f"  [{verdict}] {r['password_masked']}")
        if not r["compliant"]:
            for reason in r["reasons"]:
                print(f"         - {reason}")
    print(f"\nSummary: {compliant_count}/{len(results)} passwords are policy-compliant.")
    return results


def run_log_analysis():
    summary = analyze_logs(SAMPLE_LOG_PATH, brute_force_threshold=5)
    report_text = format_report(summary)
    print("\n" + report_text)
    return summary, report_text


def write_outputs(password_results, log_summary, report_text):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 1. Flagged brute-force IPs as CSV (sample output artifact)
    flagged_csv_path = os.path.join(OUTPUT_DIR, "flagged_ips.csv")
    with open(flagged_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["source_ip", "failed_attempts"])
        for ip, cnt in sorted(log_summary["flagged_brute_force_ips"].items(), key=lambda x: -x[1]):
            writer.writerow([ip, cnt])

    # 2. Password policy results as CSV
    pwd_csv_path = os.path.join(OUTPUT_DIR, "password_policy_results.csv")
    with open(pwd_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["password_masked", "compliant", "reasons"])
        for r in password_results:
            writer.writerow([r["password_masked"], r["compliant"], "; ".join(r["reasons"])])

    # 3. Full text report
    report_path = os.path.join(OUTPUT_DIR, "log_summary_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"\nOutputs written to: {OUTPUT_DIR}")
    print(f"  - {os.path.basename(flagged_csv_path)}")
    print(f"  - {os.path.basename(pwd_csv_path)}")
    print(f"  - {os.path.basename(report_path)}")


def main():
    print("#" * 60)
    print("# TASK 13: SentinelLog - Defensive Security Tool")
    print("#" * 60)
    password_results = run_password_policy_demo()
    log_summary, report_text = run_log_analysis()
    write_outputs(password_results, log_summary, report_text)


if __name__ == "__main__":
    main()
