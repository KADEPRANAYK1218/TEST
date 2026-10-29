"""
SentinelLog - Core Logic
Task 13: Build a Small Defensive Security Tool

Two benign defensive functions:
1. check_password_policy(password) -> validates a password against a policy
   (length, upper/lower/digit/special char, no common weak passwords).
2. analyze_logs(csv_path) -> parses a sample auth-log CSV and summarizes
   failed logins, brute-force-looking IPs, and successful logins after
   repeated failures (a classic credential-stuffing signal).

No network calls, no exploitation code. Pure analysis / validation.
"""

import csv
import re
from collections import defaultdict
from datetime import datetime

COMMON_WEAK_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "letmein",
    "admin", "welcome", "password1", "abc123", "iloveyou",
}

# --- Password Policy Checker ----------------------------------------------

def check_password_policy(password: str, min_length: int = 10) -> dict:
    """
    Validates a single password against a baseline policy:
      - minimum length
      - at least one uppercase, one lowercase, one digit, one special char
      - not a common/weak password
    Returns a dict with pass/fail + the specific reasons (never logs the
    password itself anywhere, only returns the verdict in-memory).
    """
    reasons = []

    if len(password) < min_length:
        reasons.append(f"Too short (min {min_length} characters)")
    if not re.search(r"[A-Z]", password):
        reasons.append("Missing uppercase letter")
    if not re.search(r"[a-z]", password):
        reasons.append("Missing lowercase letter")
    if not re.search(r"\d", password):
        reasons.append("Missing digit")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>/?\\|`~]", password):
        reasons.append("Missing special character")
    if password.lower() in COMMON_WEAK_PASSWORDS:
        reasons.append("Matches a common weak password list")
    if re.search(r"(.)\1{2,}", password):
        reasons.append("Contains 3+ repeated characters in a row")

    return {
        "compliant": len(reasons) == 0,
        "reasons": reasons,
    }


def check_password_file(passwords: list, min_length: int = 10) -> list:
    """Runs check_password_policy over a list of synthetic passwords."""
    results = []
    for pwd in passwords:
        verdict = check_password_policy(pwd, min_length)
        results.append({
            "password_masked": pwd[0] + "*" * (len(pwd) - 2) + pwd[-1] if len(pwd) > 2 else "*" * len(pwd),
            "compliant": verdict["compliant"],
            "reasons": verdict["reasons"],
        })
    return results


# --- Log Analyzer -----------------------------------------------------------

def analyze_logs(csv_path: str, brute_force_threshold: int = 5) -> dict:
    """
    Reads a synthetic authentication log CSV with columns:
      timestamp, source_ip, username, event, status
    (event in {"login"}, status in {"success","failure"})

    Produces a defensive summary:
      - total events
      - total failed / successful logins
      - per-IP failure counts, flagging IPs >= brute_force_threshold failures
      - accounts that had a SUCCESS immediately after >=3 failures (possible
        credential stuffing / successful brute force)
      - earliest and latest event timestamps
    """
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    total_events = len(rows)
    failures = [r for r in rows if r["status"] == "failure"]
    successes = [r for r in rows if r["status"] == "success"]

    ip_failures = defaultdict(int)
    for r in failures:
        ip_failures[r["source_ip"]] += 1

    flagged_ips = {ip: cnt for ip, cnt in ip_failures.items() if cnt >= brute_force_threshold}

    # Detect success-after-repeated-failure per username, in chronological order
    by_user = defaultdict(list)
    for r in rows:
        by_user[r["username"]].append(r)

    suspicious_accounts = []
    for user, events in by_user.items():
        events_sorted = sorted(events, key=lambda e: e["timestamp"])
        consecutive_failures = 0
        for e in events_sorted:
            if e["status"] == "failure":
                consecutive_failures += 1
            elif e["status"] == "success":
                if consecutive_failures >= 3:
                    suspicious_accounts.append({
                        "username": user,
                        "failures_before_success": consecutive_failures,
                        "success_timestamp": e["timestamp"],
                        "success_ip": e["source_ip"],
                    })
                consecutive_failures = 0

    timestamps = [r["timestamp"] for r in rows]
    earliest = min(timestamps) if timestamps else None
    latest = max(timestamps) if timestamps else None

    return {
        "total_events": total_events,
        "total_failures": len(failures),
        "total_successes": len(successes),
        "unique_ips": len(set(r["source_ip"] for r in rows)),
        "unique_users": len(set(r["username"] for r in rows)),
        "flagged_brute_force_ips": flagged_ips,
        "suspicious_accounts": suspicious_accounts,
        "earliest_event": earliest,
        "latest_event": latest,
    }


def format_report(summary: dict) -> str:
    """Formats the analyze_logs() summary dict into a readable text report."""
    lines = []
    lines.append("=" * 60)
    lines.append("SentinelLog - Authentication Log Summary")
    lines.append("=" * 60)
    lines.append(f"Time window        : {summary['earliest_event']}  ->  {summary['latest_event']}")
    lines.append(f"Total events        : {summary['total_events']}")
    lines.append(f"Successful logins   : {summary['total_successes']}")
    lines.append(f"Failed logins       : {summary['total_failures']}")
    lines.append(f"Unique source IPs   : {summary['unique_ips']}")
    lines.append(f"Unique usernames    : {summary['unique_users']}")
    lines.append("")
    lines.append("-- Brute-force-pattern IPs (>= threshold failures) --")
    if summary["flagged_brute_force_ips"]:
        for ip, cnt in sorted(summary["flagged_brute_force_ips"].items(), key=lambda x: -x[1]):
            lines.append(f"  [FLAGGED] {ip:<16} failures={cnt}")
    else:
        lines.append("  None detected.")
    lines.append("")
    lines.append("-- Accounts with success after 3+ consecutive failures --")
    if summary["suspicious_accounts"]:
        for acc in summary["suspicious_accounts"]:
            lines.append(
                f"  [SUSPICIOUS] user={acc['username']:<10} "
                f"failures_before_success={acc['failures_before_success']} "
                f"success_at={acc['success_timestamp']} from={acc['success_ip']}"
            )
    else:
        lines.append("  None detected.")
    lines.append("=" * 60)
    return "\n".join(lines)
