#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv, os, argparse, logging, re
from fpdf import FPDF, XPos, YPos

csv.field_size_limit(10_000_000)

DEFAULT_INPUT = "/home/kali/tool/csv/detection_results.csv"
DEFAULT_OUTPUT = "/home/kali/tool/forensic_report_emails.pdf"

RISK_COLORS = {
    "High": (200, 0, 0),      # Red
    "Medium": (255, 140, 0),  # Orange
    "Low": (0, 120, 0)        # Green
}

RULE_WEIGHTS = {
    "Rule1": 20,
    "Rule2": 30,
    "Rule3": 25,
    "Rule4": 10,
    "Rule5": 15
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def sanitize(text, limit=4000):
    """Sanitize text to avoid PDF issues and limit size."""
    if not text:
        return ""
    t = str(text).replace("\r", " ").replace("\n", " ")
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"(\S{40})", r"\1 ", t)
    return t[:limit]

# ---------- PDF ----------
class PDFReport(FPDF):
    """Custom PDF class for email forensic report."""
    def __init__(self):
        super().__init__()
        self.set_left_margin(20)
        self.set_right_margin(20)
        self.set_auto_page_break(True, margin=15)

        self.add_font("DejaVu", "", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
        self.add_font("DejaVu", "B", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
        self.set_font("DejaVu", "", 11)

    def header(self):
        """PDF header for all pages."""
        self.set_font("DejaVu", "B", 14)
        self.cell(0, 10, "Forensic Email Phishing Analysis Report", new_y=YPos.NEXT)
        self.ln(3)

    def footer(self):
        """PDF footer with page number."""
        self.set_y(-12)
        self.set_font("DejaVu", "", 8)
        self.cell(0, 10, f"Page {self.page_no()}")

def safe(pdf, text):
    """Safely write text in PDF with automatic wrapping."""
    width = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(width, 6, sanitize(text))
    pdf.set_x(pdf.l_margin)

# ---------- Rule Analysis ----------
def rule_analysis(row):
    """Check each phishing detection rule and return status and explanation."""
    return [
        ("Rule1",
         row.get("Rule1_Status","").upper() == "DIFFER",
         "From vs Return-Path Mismatch",
         "The visible sender address does not match the actual sending address, indicating possible spoofing."),

        ("Rule2",
         row.get("Rule2_Result","").upper() == "PHISHING",
         "SPF/DKIM Authentication Failure",
         "Authentication checks failed, suggesting the sender is not authorized to send on behalf of this domain."),

        ("Rule3",
         row.get("Rule3_Risk_Level","Low") in ("High","Medium"),
         "Suspicious Sender Domain Reputation",
         "The sending domain exhibits characteristics commonly associated with phishing or newly registered domains."),

        ("Rule4",
         str(row.get("Rule4_Missing","false")).lower() == "true",
         "Missing Message-ID Header",
         "Legitimate email infrastructure almost always includes a Message-ID header."),

        ("Rule5",
         str(row.get("Rule5_Phishing","false")).lower() == "true",
         "Phishing Content Indicators",
         "Email content contains urgency, deception, or social engineering techniques.")
    ]

def compute_score(rules):
    """Compute total risk score based on triggered rules."""
    return sum(RULE_WEIGHTS[r] for r, triggered, _, _ in rules if triggered)

def build_final_explanation(score, risk, rules):
    """Generate final forensic explanation and impact assessment."""
    triggered = [r for r, t, _, _ in rules if t]

    if score >= 70:
        verdict = "Confirmed Phishing"
        analysis = (
            "This email demonstrates multiple high-confidence phishing indicators "
            "across both technical headers and message content. "
            "The combined evidence strongly confirms malicious intent."
        )
    elif score >= 40:
        verdict = "Likely Phishing"
        analysis = (
            "This email shows several phishing characteristics. "
            "Although not all indicators are present, the observed behavior "
            "closely matches known phishing attack patterns."
        )
    else:
        verdict = "Low Risk / Suspicious"
        analysis = (
            "This email does not exhibit strong phishing indicators. "
            "Minor anomalies were observed, but there is insufficient evidence "
            "to classify it as confirmed phishing."
        )

    rule_summary = "Triggered detection rules: " + (", ".join(triggered) if triggered else "None.")

    impact = (
        "If a recipient interacts with this email, it could result in credential theft, "
        "account compromise, or unauthorized access to internal systems."
        if score >= 40 else
        "The likelihood of direct compromise is low, but continued monitoring is advised."
    )

    return f"Final Verdict: {verdict}\n\n{analysis}\n\n{rule_summary}\n\nPotential Impact Assessment:\n{impact}"

# ---------- Render Email ----------
def render_email(pdf, row, idx):
    """Render one email in the PDF report."""
    pdf.add_page()

    rules = rule_analysis(row)
    score = compute_score(rules)

    risk = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    color = RISK_COLORS[risk]

    source_ip = row.get("Source_IP","(unknown)")

    pdf.set_font("DejaVu", "B", 13)
    pdf.set_text_color(*color)
    pdf.cell(0, 8, f"Email #{idx} — Phishing Probability: {score}%", new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)

    pdf.set_font("DejaVu", "", 11)
    safe(pdf, f"From: {row.get('From','')}")
    safe(pdf, f"Subject: {row.get('Subject','(empty)')}")
    safe(pdf, f"Date: {row.get('Date','')}")
    # Add Source IP with color based on risk
    pdf.set_text_color(*color)
    safe(pdf, f"Source IP Address: {source_ip}")
    pdf.set_text_color(0, 0, 0)
    safe(pdf, f"Overall Risk Level: {risk}")

    pdf.ln(4)
    pdf.set_font("DejaVu", "B", 12)
    safe(pdf, "Detailed Rule Analysis")
    pdf.set_font("DejaVu", "", 10)

    for r, triggered, title, desc in rules:
        safe(pdf, f"- {r} [{'TRIGGERED' if triggered else 'SAFE'}]: {title}")
        safe(pdf, f"  Explanation: {desc}")

    pdf.ln(4)
    pdf.set_font("DejaVu", "B", 12)
    safe(pdf, "Final Forensic Assessment & Conclusion")
    pdf.set_font("DejaVu", "", 10)

    final_text = build_final_explanation(score, risk, rules)
    for line in final_text.split("\n"):
        safe(pdf, line)

    pdf.ln(4)
    pdf.set_font("DejaVu", "B", 12)
    safe(pdf, "Incident Response Recommendations")
    pdf.set_font("DejaVu", "", 10)

    actions = [
        "Block the sender domain and originating IP addresses immediately.",
        "Identify all recipients and check for user interaction.",
        "Reset credentials if any interaction is confirmed.",
        "Preserve the original email (EML) for forensic evidence.",
        "Update security controls and conduct phishing awareness training."
    ]

    for a in actions:
        safe(pdf, f"- {a}")

# ---------- Main ----------
def main(input_csv, output_pdf):
    """Main function to read CSV and generate PDF report."""
    pdf = PDFReport()

    with open(input_csv, encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, 1):
            render_email(pdf, row, idx)

    os.makedirs(os.path.dirname(output_pdf) or ".", exist_ok=True)
    pdf.output(output_pdf)
    logger.info("✔ Forensic report created for ALL emails with final analysis: %s", output_pdf)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_csv", nargs="?", default=DEFAULT_INPUT)
    parser.add_argument("output_pdf", nargs="?", default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    main(args.input_csv, args.output_pdf)
