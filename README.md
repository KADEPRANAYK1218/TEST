# PranayKumar-Security-Tasks — Task 13 & Task 7

Author: kpranaykumar64@gmail.com
Date: 2026-10-29
Note:- USE DIFFERENT TERMINAL FOR DIFFERENT TASKS TO GET OUTPUT 

This repository contains **two independent, self-contained projects** submitted
together under one repo. Each has its own entry point, its own `outputs/`
folder, and its own test suite. **Running one task's `app.py` never touches
the other task's files** — this was explicitly verified (see "Isolation
proof" below).

```
PranayKumar-Security-Tasks/
│
├── README.md                          <- you are here
│
├── Task-13-SentinelLog/                TASK 13: Defensive Security Tool
│   ├── app.py                          entry point — run this
│   ├── log_analyzer.py                 core logic (password policy + log analysis)
│   ├── sample_logs.csv                 synthetic input data
│   ├── test_log_analyzer.py            unit tests (15 tests)
│   ├── requirements.txt                stdlib only, no installs needed
│   └── outputs/                        generated on run
│       ├── flagged_ips.csv
│       ├── password_policy_results.csv
│       └── log_summary_report.txt
│
└── Task-07-SecureScope/                TASK 7: Threat-Model a Fictional App
    ├── app.py                          entry point — run this
    ├── threat_model.py                 STRIDE threat-generation engine
    ├── risk_assessment.py              report / CSV builder
    ├── test_risk_assessment.py         unit tests (12 tests)
    ├── threats.json                    fictional app description + data-flow diagram (input)
    ├── requirements.txt                stdlib only, no installs needed
    ├── diagrams/
    │   └── data_flow_diagram.txt       generated on run — text-based DFD
    └── outputs/                        generated on run
        ├── threat_model_report.txt
        └── threats.csv
```

---

## Problem Statements (as given)

### Task 13 — Build a Small Defensive Security Tool
> **Problem statement:** Create a simple tool for a benign task, such as
> checking password-policy compliance in synthetic data, validating a
> security checklist, or summarizing sample logs. Use a language you are
> comfortable with.
>
> **Expected deliverable:** Working prototype, sample output, and test cases.
>
> **Evaluates:** Practical execution, debugging, initiative, verification.

**What was built:** *SentinelLog* — a Python CLI tool that does both of the
suggested benign tasks at once:
1. **Password-policy compliance checker** — validates synthetic passwords
   against length, character-class, common-weak-password, and
   repeated-character rules.
2. **Log summarizer** — parses a synthetic authentication log (CSV) and
   reports total events, per-IP brute-force-pattern detection, and accounts
   that succeeded right after 3+ consecutive failures (a credential-stuffing
   signal).

### Task 7 — Threat-Model a Fictional Application
> **Problem statement:** Given a simple application description and
> data-flow diagram, identify assets, trust boundaries, potential threats,
> and practical mitigations. No exploitation is required.
>
> **Expected deliverable:** Threat model with prioritized risks and
> mitigations.
>
> **Evaluates:** Systems thinking, risk reasoning, creativity.

**What was built:** *SecureScope* — a Python tool that loads a structured
description (`threats.json`) of a fictional e-commerce app called
**QuickCart** (components, data flows, trust boundaries, assets), applies a
rule-based **STRIDE** threat catalogue to every flow that crosses a trust
boundary, scores each threat on a Likelihood × Impact risk matrix, and
outputs a prioritized list of threats with concrete mitigations — as a text
report, a CSV, and a simple ASCII data-flow diagram.

---

## Setup

Both tasks need only **Python 3.8+**.

```bash
# clone / unzip the repo, then from the repo root:
cd PranayKumar-Security-Tasks
```

Both **Task 13** and **Task 7** use only the Python standard library —
nothing to `pip install` for either one.

---

## How to run

### Option A — VS Code
1. Open the `PranayKumar-Security-Tasks` folder in VS Code.
2. Open the integrated terminal (`` Ctrl+` ``).
3. Pick the task's folder and run `app.py` as shown below, **or** open
   `app.py` for the task you want and click **Run ▶** (top-right) /
   press `F5` — make sure the correct file is the active tab, since each
   folder has its own `app.py`.

### Option B — Python terminal / any shell

**Run Task 13 only** (produces only Task 13 output, writes only to
`Task-13-SentinelLog/outputs/`):
```bash
cd Task-13-SentinelLog
python app.py
```

**Run Task 7 only** (produces only Task 7 output, writes only to
`Task-07-SecureScope/outputs/` and `diagrams/`):
```bash
cd Task-07-SecureScope
python app.py
```

Each `app.py` is a **fully independent entry point** — it imports only from
its own folder and writes only inside its own folder. Running one never
creates, modifies, or references files in the other task's folder.

### Running the tests

```bash
# Task 13
cd Task-13-SentinelLog
python -m unittest test_log_analyzer.py -v

# Task 7
cd Task-07-SecureScope
python -m unittest test_risk_assessment.py -v
```

---

## Test Results (actual run output)

### Task 13 — `test_log_analyzer.py` — 15/15 passed
```
test_brute_force_ip_flagged ... ok
test_clean_account_not_flagged ... ok
test_low_volume_ip_not_flagged ... ok
test_malformed_csv_raises_cleanly ... ok
test_success_and_failure_sum_to_total ... ok
test_suspicious_account_detected ... ok
test_total_events_counted ... ok
test_unique_ip_and_user_counts_are_sane ... ok
test_missing_digit_fails ... ok
test_missing_special_char_fails ... ok
test_missing_uppercase_fails ... ok
test_repeated_chars_fails ... ok
test_strong_password_passes ... ok
test_too_short_password_fails ... ok
test_weak_common_password_fails ... ok

Ran 15 tests in 0.002s
OK
```

### Task 7 — `test_risk_assessment.py` — 12/12 passed
```
test_admin_flow_flags_elevation_of_privilege ... ok
test_application_loads ... ok
test_assets_sorted_by_sensitivity ... ok
test_critical_asset_present ... ok
test_every_threat_has_mitigation ... ok
test_every_threat_has_valid_stride_category ... ok
test_internal_only_flow_not_in_threats ... ok
test_missing_file_raises ... ok
test_payment_flow_flags_information_disclosure ... ok
test_threats_generated ... ok
test_threats_sorted_by_severity ... ok
test_trust_boundaries_loaded ... ok

Ran 12 tests in 0.002s
OK
```

---

## Sample output (summary)

**Task 13:** On the included `sample_logs.csv` (25 synthetic events),
SentinelLog correctly flags IP `203.0.113.77` as brute-force (11 failures,
threshold 5) and flags user `bob` as suspicious (3 consecutive failures
immediately followed by a success). Out of 7 synthetic test passwords,
3/7 are policy-compliant.

**Task 7:** On the QuickCart app description, SecureScope generates **21
prioritized STRIDE threats** across 4 trust boundaries (7 High, 9 Medium,
5 Low), covering Spoofing, Tampering, Repudiation, Information Disclosure,
Denial of Service, and Elevation of Privilege — each with a specific
mitigation. Full detail is in `outputs/threat_model_report.txt` and
`outputs/threats.csv`.

---

## Isolation proof

Verified by running each task from a clean state and checking the
filesystem afterward:
- Running `Task-13-SentinelLog/app.py` alone creates **only**
  `Task-13-SentinelLog/outputs/*` — `Task-07-SecureScope/` is left with no
  `outputs/` and no `diagrams/`.
- Each `app.py` resolves all paths relative to its **own** file location
  (`os.path.dirname(os.path.abspath(__file__))`), so it works correctly
  regardless of which directory you launch it from.

---

## Notes on genuine work / verification

- All counts and figures quoted above (15 tests, 12 tests, 21 threats,
  11 failures on the flagged IP, 3/7 compliant passwords) are taken
  directly from actual execution output on 2026-10-29, not estimated.
- Sample data (`sample_logs.csv`, `threats.json`) is synthetic/fictional,
  as the problem statements require — no real credentials, logs, or
  production systems are involved.
- No exploitation code, live scanning, or network calls are included in
  either tool, in line with Task 7's "No exploitation is required" and the
  defensive/benign scope of Task 13.
