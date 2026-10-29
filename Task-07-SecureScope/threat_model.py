"""
SecureScope - Core Threat Modeling Logic
Task 7: Threat-Model a Fictional Application

Loads a JSON description of a fictional app (QuickCart - an e-commerce app)
with its data-flow diagram (components, flows, trust boundaries, assets),
then applies a STRIDE-based threat catalogue to each trust-boundary-crossing
data flow to generate prioritized threats + mitigations.

No exploitation, no live scanning - this is pure structured risk reasoning
over a static description, exactly as the problem statement asks.
"""

import json

STRIDE_CATEGORIES = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

# Likelihood x Impact -> qualitative risk rating (simple 3x3 risk matrix)
RISK_MATRIX = {
    (1, 1): "Low", (1, 2): "Low", (1, 3): "Medium",
    (2, 1): "Low", (2, 2): "Medium", (2, 3): "High",
    (3, 1): "Medium", (3, 2): "High", (3, 3): "Critical",
}


def load_application(json_path: str) -> dict:
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _component_name(components: list, comp_id: str) -> str:
    for c in components:
        if c["id"] == comp_id:
            return c["name"]
    return comp_id


def generate_threats(app_data: dict) -> list:
    """
    Walks every data flow that crosses a trust boundary and generates a
    STRIDE threat entry with a likelihood/impact score and a mitigation.
    This encodes a threat-modeler's reasoning as repeatable rules so the
    tool produces a consistent, explainable prioritized list.
    """
    components = app_data["application"]["components"]
    flows = app_data["application"]["data_flows"]

    threats = []
    tid_counter = 1

    # --- Rule set: one or more STRIDE threats per flow, chosen by context ---
    for flow in flows:
        if not flow.get("crosses_trust_boundary"):
            continue

        src = _component_name(components, flow["from"])
        dst = _component_name(components, flow["to"])
        data = flow["data"]
        flow_id = f"{flow['from']}->{flow['to']}"

        generated = []

        # Spoofing - any flow where an external entity authenticates to a process
        if "credential" in data.lower() or "login" in data.lower():
            generated.append(("S", 2, 3,
                f"An attacker could spoof a legitimate {src} by stealing or guessing "
                f"credentials used in the flow to {dst}, impersonating a real user or admin."))

        # Tampering - any write/update flow
        if any(k in data.lower() for k in ["edit", "update", "write", "create"]):
            generated.append(("T", 2, 2,
                f"Data in transit or at rest between {src} and {dst} ({data}) could be "
                f"tampered with if integrity controls (TLS, signed requests, DB constraints) are weak."))

        # Repudiation - any flow that changes state (orders, inventory) without strong logging
        if any(k in data.lower() for k in ["order", "inventory", "checkout"]):
            generated.append(("R", 1, 2,
                f"A user or admin could deny having performed an action affecting {data} "
                f"if {dst} does not keep tamper-evident audit logs tied to an identity."))

        # Information Disclosure - any flow carrying PII, payment, or credential data
        if any(k in data.lower() for k in ["pii", "payment", "credential", "customer", "card"]):
            generated.append(("I", 2, 3,
                f"Sensitive data ({data}) flowing between {src} and {dst} could be exposed "
                f"via interception, misconfigured access controls, or verbose logging/error messages."))

        # Denial of Service - external-facing entry points
        if flow["from"] in ("web_client", "admin_client", "payment_gateway"):
            generated.append(("D", 2, 2,
                f"{dst} is reachable from {src} and could be overwhelmed by high-volume or "
                f"malformed requests (e.g., credential-stuffing bursts, large payloads)."))

        # Elevation of Privilege - admin surfaces specifically
        if "admin" in src.lower() or "admin" in dst.lower():
            generated.append(("E", 1, 3,
                f"A regular authenticated user, or an attacker who compromises {src}, could "
                f"attempt to reach {dst} and perform admin-only actions if authorization checks "
                f"are missing or inconsistently enforced server-side."))

        for category, likelihood, impact, description in generated:
            risk = RISK_MATRIX[(likelihood, impact)]
            threats.append({
                "id": f"T{tid_counter:03d}",
                "flow": flow_id,
                "flow_description": f"{src} -> {dst} ({data})",
                "stride_category": STRIDE_CATEGORIES[category],
                "likelihood": likelihood,
                "impact": impact,
                "risk_rating": risk,
                "description": description,
                "mitigation": MITIGATIONS[category],
            })
            tid_counter += 1

    # Sort by risk severity, highest first
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    threats.sort(key=lambda t: severity_order[t["risk_rating"]])
    return threats


MITIGATIONS = {
    "S": "Enforce MFA for admin and customer accounts, use short-lived signed session "
         "tokens, rate-limit login attempts, and bind sessions to device/IP heuristics.",
    "T": "Use TLS 1.2+ everywhere, validate/sanitize all inputs server-side, apply "
         "parameterized queries, and enforce DB-level constraints and request signing "
         "for admin writes.",
    "R": "Emit structured, append-only audit logs (who/what/when) tied to authenticated "
         "identity for every state-changing action; protect logs from tampering.",
    "I": "Encrypt sensitive data at rest and in transit, apply least-privilege DB access, "
         "never store raw payment data (use the gateway's tokenization), and scrub PII "
         "from logs and error messages.",
    "D": "Apply rate limiting / WAF rules at the perimeter, use CAPTCHA after repeated "
         "failures, set request size limits, and enable autoscaling with circuit breakers.",
    "E": "Enforce server-side authorization checks (not just UI hiding) on every admin "
         "endpoint, use role-based access control, and isolate the admin panel on a "
         "separate network path with its own auth.",
}


def summarize_assets(app_data: dict) -> list:
    """Returns assets sorted by sensitivity, highest first."""
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    assets = app_data["assets"]
    return sorted(assets, key=lambda a: order.get(a["sensitivity"], 99))


def summarize_trust_boundaries(app_data: dict) -> list:
    return app_data["application"]["trust_boundaries"]
