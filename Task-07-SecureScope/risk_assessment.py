"""
SecureScope - Risk Assessment / Report Builder
Task 7: Threat-Model a Fictional Application

Takes the threat list produced by threat_model.generate_threats() and
builds a readable, prioritized report (text + PDF), plus a simple
text-based data-flow diagram.
"""

import os


def format_text_report(app_data: dict, assets: list, boundaries: list, threats: list) -> str:
    app = app_data["application"]
    lines = []
    lines.append("=" * 70)
    lines.append(f"SecureScope - Threat Model Report: {app['name']}")
    lines.append("=" * 70)
    lines.append(app["description"])
    lines.append("")

    lines.append("-" * 70)
    lines.append("ASSETS (by sensitivity)")
    lines.append("-" * 70)
    for a in assets:
        lines.append(f"  [{a['sensitivity']:<8}] {a['id']}: {a['name']}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("TRUST BOUNDARIES")
    lines.append("-" * 70)
    for b in boundaries:
        lines.append(f"  {b['id']}: {b['name']}")
    lines.append("")

    lines.append("-" * 70)
    lines.append(f"PRIORITIZED THREATS (STRIDE)  -  {len(threats)} total")
    lines.append("-" * 70)
    severity_counts = {}
    for t in threats:
        severity_counts[t["risk_rating"]] = severity_counts.get(t["risk_rating"], 0) + 1
    lines.append("Risk breakdown: " + ", ".join(f"{k}={v}" for k, v in
                  sorted(severity_counts.items(), key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}[x[0]])))
    lines.append("")

    for t in threats:
        lines.append(f"[{t['risk_rating'].upper()}] {t['id']} - {t['stride_category']}")
        lines.append(f"    Flow        : {t['flow_description']}")
        lines.append(f"    Likelihood  : {t['likelihood']}/3   Impact: {t['impact']}/3")
        lines.append(f"    Threat      : {t['description']}")
        lines.append(f"    Mitigation  : {t['mitigation']}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def build_ascii_dfd(app_data: dict) -> str:
    """A simple text-based data-flow diagram (no exploitation, just layout)."""
    lines = []
    lines.append("DATA FLOW DIAGRAM (simplified, text form)")
    lines.append("")
    lines.append("  [Customer Browser]                [Admin Staff Browser]")
    lines.append("         |  (tb1: Internet)                 |  (tb2: Internet/VPN)")
    lines.append("         v                                  v")
    lines.append("  +------------------+              +-------------------+")
    lines.append("  |   Web/API Server  |<------------>|   Admin Panel     |")
    lines.append("  |   (QuickCart App) |              +-------------------+")
    lines.append("  +------------------+")
    lines.append("     |     |      |")
    lines.append("     |     |      | (tb3: 3rd-party)")
    lines.append("     |     |      v")
    lines.append("     |     |   +----------------------+")
    lines.append("     |     |   |  Payment Gateway (3P) |")
    lines.append("     |     |   +----------------------+")
    lines.append("     |     v")
    lines.append("     |  +------------------------+   (tb4: app<->data)")
    lines.append("     |  | Orders & Customer DB    |")
    lines.append("     |  +------------------------+")
    lines.append("     v")
    lines.append("  +------------------------+")
    lines.append("  | Product Catalog DB      |")
    lines.append("  +------------------------+")
    lines.append("")
    lines.append("  Trust boundaries (tb1-tb4) mark where data crosses from a less-trusted")
    lines.append("  zone into a more-trusted one; every crossing is analyzed for STRIDE threats.")
    return "\n".join(lines)


def write_outputs(output_dir: str, diagrams_dir: str, text_report: str, ascii_dfd: str, threats: list):
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(diagrams_dir, exist_ok=True)

    report_path = os.path.join(output_dir, "threat_model_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(text_report)

    dfd_path = os.path.join(diagrams_dir, "data_flow_diagram.txt")
    with open(dfd_path, "w", encoding="utf-8") as f:
        f.write(ascii_dfd)

    # CSV of threats for easy review / spreadsheet import
    import csv
    csv_path = os.path.join(output_dir, "threats.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "risk_rating", "stride_category", "flow", "likelihood", "impact", "description", "mitigation"])
        for t in threats:
            writer.writerow([t["id"], t["risk_rating"], t["stride_category"], t["flow_description"],
                              t["likelihood"], t["impact"], t["description"], t["mitigation"]])

    return report_path, dfd_path, csv_path
