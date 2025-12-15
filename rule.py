#!/usr/bin/env python3
# coding: utf-8
"""
Email CSV phishing detection - Cleaned version
Reads INPUT_CSV, writes OUTPUT_CSV
Dependencies: dns.resolver (dnspython), tldextract, beautifulsoup4
"""

import csv
import re
from email.utils import parseaddr
import dns.resolver
import tldextract
from bs4 import BeautifulSoup

INPUT_CSV = "/home/stiti/isthistheend/csv/email.csv"
OUTPUT_CSV = "/home/stiti/isthistheend/csv/color_results.csv"

csv.field_size_limit(10000000)


class PhishingDetector:
    def __init__(self):
        self.SUSPICIOUS_TLDS = {
            "top", "xyz", "zip", "click", "quest", "shop", "online",
            "ink", "center", "group", "io", "club", "site"
        }

        suspicious_words = [
            "login", "log in", "password", "pass", "verify", "verification",
            "reset", "update", "urgent", "bank", "account", "security",
            "confirm", "click", "unlock", "suspend", "locked",
            "immediately", "action required", "suspended", "billing", "invoice"
        ]

        self.SUSPICIOUS_PATTERNS = [
            re.compile(r"\b" + re.escape(w) + r"\b", re.IGNORECASE)
            for w in suspicious_words
        ]

        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = 5.0
        self.resolver.timeout = 3.0
        self.mx_cache = {}

    def rule1_from_return(self, from_h, return_h):
        def get_email(v):
            try:
                return parseaddr(str(v))[1].lower()
            except Exception:
                m = re.findall(r'[\w\.-]+@[\w\.-]+', str(v) or "")
                return m[0].lower() if m else ""

        f = get_email(from_h)
        r = get_email(return_h)
        status = "MATCH" if f and (f == r) else "DIFFER"
        return {
            "Rule1_Status": status,
            "Rule1_From_Email": f,
            "Rule1_Return_Email": r
        }

    def rule2_auth(self, auth):
        a = str(auth or "").lower()
        spf = "NONE"
        dkim = "NONE"
        if "spf=pass" in a:
            spf = "PASS"
        elif "spf=fail" in a or "spf=hardfail" in a:
            spf = "FAIL"
        if "dkim=pass" in a:
            dkim = "PASS"
        elif "dkim=fail" in a:
            dkim = "FAIL"
        result = "NORMAL" if (spf == "PASS" and dkim == "PASS") else "PHISHING"
        return {"Rule2_SPF": spf, "Rule2_DKIM": dkim, "Rule2_Result": result}

    def rule3_domain(self, from_h):
        def extract_email(v):
            try:
                return parseaddr(str(v))[1]
            except Exception:
                m = re.findall(r'[\w\.-]+@[\w\.-]+', str(v) or "")
                return m[0] if m else ""

        email_addr = (extract_email(from_h) or "").strip()
        if "@" not in email_addr:
            return {
                "Rule3_Risk_Score": 60,
                "Rule3_Risk_Level": "High",
                "Rule3_Domain": "",
                "Rule3_Brand_Impersonation": None
            }

        domain = email_addr.split("@", 1)[1].lower()
        score = 0

        try:
            ext = tldextract.extract(domain)
            tld = ext.suffix.lower() if ext.suffix else ""
            if any(part in self.SUSPICIOUS_TLDS for part in tld.split(".")):
                score += 25
        except Exception:
            pass

        if not self._has_mx_records(domain):
            score += 25

        risk = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
        return {
            "Rule3_Risk_Score": score,
            "Rule3_Risk_Level": risk,
            "Rule3_Domain": domain,
            "Rule3_Brand_Impersonation": None
        }

    def _has_mx_records(self, domain):
        if domain in self.mx_cache:
            return self.mx_cache[domain]
        try:
            self.resolver.resolve(domain, "MX")
            ok = True
        except Exception:
            try:
                self.resolver.resolve(domain, "A")
                ok = True
            except Exception:
                ok = False
        self.mx_cache[domain] = ok
        return ok

    def rule4_message_id(self, msg_id):
        mid = str(msg_id or "").strip()
        return {"Rule4_Message_ID": mid, "Rule4_Missing": (mid == "")}

    def rule5_content(self, body_text, body_html):
        text = (body_text or "")[:200000]
        html = (body_html or "")[:200000]
        suspicious = any(p.search(text + " " + html) for p in self.SUSPICIOUS_PATTERNS)
        return {
            "Rule5_Phishing": suspicious,
            "Rule5_Reasons": "suspicious_words" if suspicious else "clean",
            "Rule5_Suspicious_Words": suspicious,
            "Rule5_Link_Mismatch": False
        }


def main():
    det = PhishingDetector()

    low_risk = 0
    medium_risk = 0
    high_risk = 0
    total = 0

    fields = [
        "Filename", "Subject",
        "From", "Return-Path", "Authentication-Results",
        "Message-ID", "Date",
        "Rule1_Status", "Rule1_From_Email", "Rule1_Return_Email",
        "Rule2_SPF", "Rule2_DKIM", "Rule2_Result",
        "Rule3_Risk_Score", "Rule3_Risk_Level", "Rule3_Domain", "Rule3_Brand_Impersonation",
        "Rule4_Message_ID", "Rule4_Missing",
        "Rule5_Phishing", "Rule5_Reasons",
        "Rule5_Suspicious_Words", "Rule5_Link_Mismatch",
        "Total_Risk_Score"
    ]

    with open(INPUT_CSV, "r", encoding="utf-8") as inp, \
         open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as out:

        reader = csv.DictReader(inp)
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()

        for idx, row in enumerate(reader, start=1):
            total += 1
            print(f"[PROGRESS] Now at email #{idx}")

            from_h = row.get("From", "")

            r1 = det.rule1_from_return(from_h, row.get("Return-Path", ""))
            r2 = det.rule2_auth(row.get("Authentication-Results", ""))
            r3 = det.rule3_domain(from_h)
            r4 = det.rule4_message_id(row.get("Message-ID", ""))
            r5 = det.rule5_content(row.get("Body_Text", ""), row.get("Body_HTML", ""))

            risk_score = 0
            if r1["Rule1_Status"] == "DIFFER":
                risk_score += 15
            if r2["Rule2_Result"] == "PHISHING":
                risk_score += 20
            if r3["Rule3_Risk_Level"] == "High":
                risk_score += 30
            elif r3["Rule3_Risk_Level"] == "Medium":
                risk_score += 15
            if r4["Rule4_Missing"]:
                risk_score += 5
            if r5["Rule5_Phishing"]:
                risk_score += 30

            if risk_score < 30:
                low_risk += 1
            elif risk_score <= 60:
                medium_risk += 1
            else:
                high_risk += 1

            out_row = {
                "Filename": row.get("Filename", ""),
                "Subject": row.get("Subject", ""),
                "From": from_h,
                "Return-Path": row.get("Return-Path", ""),
                "Authentication-Results": row.get("Authentication-Results", ""),
                "Message-ID": row.get("Message-ID", ""),
                "Date": row.get("Date", ""),
                **r1, **r2, **r3, **r4, **r5,
                "Total_Risk_Score": risk_score
            }

            writer.writerow({k: out_row.get(k, "") for k in fields})

    GREEN = "\033[92m"
    ORANGE = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"

    print("\n===== PHISHING RISK SUMMARY =====")
    print(f"{GREEN}🟢 LOW RISK    (<30):    {low_risk} emails{RESET}")
    print(f"{ORANGE}🟠 MEDIUM RISK (30–60):  {medium_risk} emails{RESET}")
    print(f"{RED}🔴 HIGH RISK   (>60):    {high_risk} emails{RESET}")
    print("================================")
    print(f"Total processed emails: {total}\n")


if __name__ == "__main__":
    main()

