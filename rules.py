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

INPUT_CSV = "/home/kali/tool/csv/email.csv"
OUTPUT_CSV = "/home/kali/tool/csv/detection_results.csv"

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
            tld_parts = tld.split(".") if tld else []
            if any(part in self.SUSPICIOUS_TLDS for part in tld_parts):
                score += 25
        except Exception:
            pass

        if not self._has_mx_records(domain):
            score += 25

        brand_imp = None
        risk = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
        return {
            "Rule3_Risk_Score": score,
            "Rule3_Risk_Level": risk,
            "Rule3_Domain": domain,
            "Rule3_Brand_Impersonation": brand_imp
        }

    def _has_mx_records(self, domain):
        if not domain:
            return False
        if domain in self.mx_cache:
            return self.mx_cache[domain]
        try:
            answers = self.resolver.resolve(domain, "MX")
            ok = len(answers) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            try:
                aans = self.resolver.resolve(domain, "A")
                ok = len(aans) > 0
            except Exception:
                ok = False
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
        URL_RE = re.compile(r"https?://[^\s\"\'<>]+", re.IGNORECASE)

        def contains_suspicious(txt):
            sample = txt or ""
            for patt in self.SUSPICIOUS_PATTERNS:
                if patt.search(sample):
                    return True
            return False

        def extract_links_from_html(h):
            links = []
            try:
                soup = BeautifulSoup(h or "", "html.parser")
                for a in soup.find_all("a", href=True):
                    visible = a.get_text(strip=True) or ""
                    actual = a.get("href") or ""
                    links.append((visible, actual))
                for img in soup.find_all("img"):
                    src = (img.get("src") or "").strip()
                    parent = img.find_parent("a")
                    href = parent.get("href").strip() if parent and parent.get("href") else src
                    if href:
                        links.append(("[IMAGE]", href))
            except Exception:
                pass
            return links

        def extract_links_from_text(t):
            try:
                found = URL_RE.findall(t or "")
                return [(u, u) for u in found]
            except Exception:
                return []

        def check_mismatch(visible, actual):
            try:
                v = (visible or "").strip()
                a = (actual or "").strip()
                if not a:
                    return False
                if v == "[IMAGE]":
                    return False
                if re.match(r"^https?://", v, re.IGNORECASE):
                    return v.lower() != a.lower()
                try:
                    actual_domain = tldextract.extract(a).registered_domain or ""
                    visible_domain = tldextract.extract(v).registered_domain or ""
                    if actual_domain and visible_domain:
                        return actual_domain.lower() != visible_domain.lower()
                except Exception:
                    pass
                return v.lower() != a.lower()
            except Exception:
                return False

        suspicious_found = contains_suspicious(text + " " + html)
        link_mismatch = False

        links = []
        links.extend(extract_links_from_html(html))
        links.extend(extract_links_from_text(text))

        for vis, act in links[:200]:
            if check_mismatch(vis, act):
                link_mismatch = True
                break

        is_phish = suspicious_found or link_mismatch
        reasons = []
        if suspicious_found:
            reasons.append("suspicious_words")
        if link_mismatch:
            reasons.append("link_mismatch")

        return {
            "Rule5_Phishing": is_phish,
            "Rule5_Reasons": " | ".join(reasons) if reasons else "clean",
            "Rule5_Suspicious_Words": suspicious_found,
            "Rule5_Link_Mismatch": link_mismatch
        }


def main():
    det = PhishingDetector()
    total = 0
    flagged = 0

    fields = [
        "Filename", "Subject",
        "From", "Return-Path", "Authentication-Results",
        "Message-ID", "Date",
        "Rule1_Status", "Rule1_From_Email", "Rule1_Return_Email",
        "Rule2_SPF", "Rule2_DKIM", "Rule2_Result",
        "Rule3_Risk_Score", "Rule3_Risk_Level", "Rule3_Domain", "Rule3_Brand_Impersonation",
        "Rule4_Message_ID", "Rule4_Missing",
        "Rule5_Phishing", "Rule5_Reasons",
        "Rule5_Suspicious_Words", "Rule5_Link_Mismatch"
    ]

    try:
        with open(INPUT_CSV, "r", encoding="utf-8") as inp, \
             open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as out:

            reader = csv.DictReader(inp)
            writer = csv.DictWriter(out, fieldnames=fields)
            writer.writeheader()

            for idx, row in enumerate(reader, start=1):
                total += 1

                print(f"[PROGRESS] Now at email #{idx}")

                filename = row.get("Filename", "") or f"row_{idx}"
                subject = row.get("Subject", "")

                from_h = row.get("From", "")

                r1 = det.rule1_from_return(from_h, row.get("Return-Path", ""))
                r2 = det.rule2_auth(row.get("Authentication-Results", ""))
                r3 = det.rule3_domain(from_h)
                r4 = det.rule4_message_id(row.get("Message-ID", ""))
                r5 = det.rule5_content(row.get("Body_Text", ""), row.get("Body_HTML", ""))

                is_phishing = bool(r5.get("Rule5_Phishing", False)) or \
                              (r2.get("Rule2_Result") == "PHISHING") or \
                              (r3.get("Rule3_Risk_Level") == "High")
                if is_phishing:
                    flagged += 1

                out_row = {
                    "Filename": filename,
                    "Subject": subject,
                    "From": from_h,
                    "Return-Path": row.get("Return-Path", ""),
                    "Authentication-Results": row.get("Authentication-Results", ""),
                    "Message-ID": row.get("Message-ID", ""),
                    "Date": row.get("Date", ""),
                    **r1, **r2, **r3, **r4, **r5
                }

                filtered = {k: out_row.get(k, "") for k in fields}
                writer.writerow(filtered)

    except FileNotFoundError as e:
        print(f"[ERROR] Input file not found: {e}")
        return
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        return

    print(f"[DONE] Processed {total} emails. Flagged as phishing: {flagged}.")
    print(f"Results saved to: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
