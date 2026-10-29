"""
SecureScope - Entry Point (Task 07 only)
Run: python app.py

This is the ONLY entry point for Task 7. Running this file produces
Task-07 output exclusively (threat model report, ASCII data-flow diagram,
and threats.csv). It does not touch Task 13's files at all.
"""

import os
from threat_model import load_application, generate_threats, summarize_assets, summarize_trust_boundaries
from risk_assessment import format_text_report, build_ascii_dfd, write_outputs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
THREATS_JSON = os.path.join(BASE_DIR, "threats.json")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
DIAGRAMS_DIR = os.path.join(BASE_DIR, "diagrams")


def main():
    print("#" * 60)
    print("# TASK 07: SecureScope - Threat-Model a Fictional Application")
    print("#" * 60)

    app_data = load_application(THREATS_JSON)
    assets = summarize_assets(app_data)
    boundaries = summarize_trust_boundaries(app_data)
    threats = generate_threats(app_data)

    text_report = format_text_report(app_data, assets, boundaries, threats)
    ascii_dfd = build_ascii_dfd(app_data)

    print(text_report)
    print()
    print(ascii_dfd)

    report_path, dfd_path, csv_path = write_outputs(OUTPUT_DIR, DIAGRAMS_DIR, text_report, ascii_dfd, threats)

    print("\nOutputs written:")
    print(f"  - {report_path}")
    print(f"  - {dfd_path}")
    print(f"  - {csv_path}")


if __name__ == "__main__":
    main()
