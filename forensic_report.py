#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv, os, argparse, logging, re
from fpdf import FPDF, XPos, YPos

csv.field_size_limit(10_000_000)

DEFAULT_INPUT = "/home/kali/tool/csv/detection_results.csv"
DEFAULT_OUTPUT = "/home/kali/tool/forensic_report_emails.pdf"

# === Risk colors ===
RISK_COLORS = {
    "High": (200, 0, 0),
    "Medium": (255, 140, 0),
    "Low": (0, 120, 0)
}

# === EXACT weights from phishing detector ===
RULE_WEIGHTS = {
    "Rule1_DIFFER": 15,
    "Rule2_PHISHING": 20,
    "Rule3_HIGH": 30,
    "Rule3_MEDIUM": 15,
    "Rule4_MISSING": 5,
    "Rule5_PHISHING": 30
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- Utils ----------
def sanitize(text, limit=4000):
    if not text:
        return ""
    t = str(text).replace("\r", " ").replace("\n", " ")
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"(\S{40})", r"\1 ", t)
    return t[:limit]

# ---------- PDF ----------
class PDFReport(FPDF):
    def __init__(self):
        super().__init__()
        self.set_left_margin(20)
        self.set_right_margin(20)
        self.set_auto_page_break(True, margin=15)

        self.add_font("DejaVu", "", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
        self.add_font("DejaVu", "B", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
        self.set_font("DejaVu", "", 11)

    def header(self):
        self.set_font("DejaVu", "B", 14)
        self.cell(0, 10, "Forensic Email Phishing Analysis Report", new_y=YPos.NEXT)
        self.ln(3)

    def footer(self):
        self.set_y(-12)
        self.set_font("DejaVu", "", 8)
        self.cell(0, 10, f"Page {self.page_no()}")

def safe(pdf, text):
    width = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(width, 6, sanitize(text))
    pdf.set_x(pdf.l_margin)

# ---------- Rule Analysis ----------
def rule_analysis(row):
    rules = []

    rules.append((
        "Rule1_DIFFER",
        row.get("Rule1_Status","").upper() == "DIFFER",
        "From vs Return-Path Mismatch",
        "The visible sender address does not match the actual bounce address. "
        "This indicates possible email spoofing or sender impersonation."
    ))

    rules.append((
        "Rule2_PHISHING",
        row.get("Rule2_Result","").upper() == "PHISHING",
        "SPF / DKIM Authentication Failure",
        "Email authentication mechanisms failed. The sender is not authorized "
        "to send on behalf of this domain."
    ))

    r3 = row.get("Rule3_Risk_Level","Low")
    rules.append((
        "Rule3_HIGH",
        r3 == "High",
        "High-Risk Sender Domain",
        "The sender domain shows strong indicators of phishing, including "
        "brand impersonation, typosquatting, or suspicious TLD usage."
    ))
    rules.append((
        "Rule3_MEDIUM",
        r3 == "Medium",
        "Medium-Risk Sender Domain",
        "The sender domain exhibits suspicious characteristics but lacks "
        "definitive proof of malicious intent."
    ))

    rules.append((
        "Rule4_MISSING",
        str(row.get("Rule4_Missing","false")).lower() == "true",
        "Missing Message-ID Header",
        "Legitimate email servers almost always include a Message-ID. "
        "Its absence suggests non-standard or malicious sending infrastructure."
    ))

    rules.append((
        "Rule5_PHISHING",
        str(row.get("Rule5_Phishing","false")).lower() == "true",
        "Phishing Content Indicators",
        "The email content contains social engineering techniques such as urgency, "
        "credential harvesting, or deceptive links."
    ))

    return rules

def compute_score(rules):
    score = 0
    for r, triggered, _, _ in rules:
        if triggered:
            score += RULE_WEIGHTS.get(r, 0)
    return min(score, 100)

# ---------- Explanations ----------
def attack_scenario(score):
    if score >= 70:
        return (
            "This email is part of an active phishing attack. The attacker is "
            "attempting to impersonate a trusted entity to steal credentials "
            "or deliver malware."
        )
    elif score >= 40:
        return (
            "This email likely supports a phishing campaign. The infrastructure "
            "and content suggest malicious intent, although execution may vary."
        )
    elif score >= 20:
        return (
            "This email shows anomalies commonly seen in early-stage or low-effort "
            "phishing attempts."
        )
    else:
        return (
            "No clear attack pattern detected. The email appears mostly legitimate."
        )

def response_actions(score):
    if score >= 70:
        return [
            "Immediately block the sender domain and source IP.",
            "Identify all recipients and isolate affected endpoints.",
            "Force password resets for potentially compromised accounts.",
            "Preserve original EML files for forensic evidence.",
            "Escalate incident to SOC / Incident Response team."
        ]
    elif score >= 40:
        return [
            "Monitor for user interaction with the email.",
            "Warn recipients and advise not to click any links.",
            "Add sender to temporary blocklist.",
            "Review email gateway and authentication logs."
        ]
    elif score >= 20:
        return [
            "Flag the email as suspicious.",
            "Educate users to verify sender authenticity.",
            "Continue monitoring similar messages."
        ]
    else:
        return [
            "No action required beyond standard monitoring."
        ]

# ---------- Render ----------
def render_email(pdf, row, idx):
    pdf.add_page()

    rules = rule_analysis(row)
    score = compute_score(rules)

    risk = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    color = RISK_COLORS[risk]

    pdf.set_font("DejaVu", "B", 13)
    pdf.set_text_color(*color)
    pdf.cell(0, 8, f"Email #{idx} — Phishing Risk Score: {score} / 100", new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)

    safe(pdf, f"From: {row.get('From','')}")
    safe(pdf, f"Subject: {row.get('Subject','(empty)')}")
    safe(pdf, f"Date: {row.get('Date','')}")
    safe(pdf, f"Overall Risk Level: {risk}")

    pdf.ln(4)
    pdf.set_font("DejaVu", "B", 12)
    safe(pdf, "Triggered Detection Rules")
    pdf.set_font("DejaVu", "", 10)

    for r, triggered, title, desc in rules:
        if triggered:
            safe(pdf, f"- {r}: {title}")
            safe(pdf, f"  Details: {desc}")

    pdf.ln(4)
    pdf.set_font("DejaVu", "B", 12)
    safe(pdf, "Attack Scenario Analysis")
    pdf.set_font("DejaVu", "", 10)
    safe(pdf, attack_scenario(score))

    pdf.ln(4)
    pdf.set_font("DejaVu", "B", 12)
    safe(pdf, "Recommended Incident Response Actions")
    pdf.set_font("DejaVu", "", 10)

    for a in response_actions(score):
        safe(pdf, f"- {a}")

# ---------- Main ----------
def main(input_csv, output_pdf):
    pdf = PDFReport()

    with open(input_csv, encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, 1):
            render_email(pdf, row, idx)

    os.makedirs(os.path.dirname(output_pdf) or ".", exist_ok=True)
    pdf.output(output_pdf)
    logger.info("✔ Forensic phishing report created: %s", output_pdf)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_csv", nargs="?", default=DEFAULT_INPUT)
    parser.add_argument("output_pdf", nargs="?", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    main(args.input_csv, args.output_pdf)
