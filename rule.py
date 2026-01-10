#!/usr/bin/env python3
# coding: utf-8


import csv
import re
from email.utils import parseaddr
import dns.resolver
import tldextract
from bs4 import BeautifulSoup
from difflib import SequenceMatcher

INPUT_CSV = "/home/stiti/isthistheend/csv/email.csv"
OUTPUT_CSV = "/home/stiti/isthistheend/csv/test.csv"

csv.field_size_limit(10000000)

class PhishingDetector:
    def __init__(self):
        self.SUSPICIOUS_TLDS = {"top","xyz","zip","click","quest","shop","online","ink","center","group","io","club","site"}

        self.BRANDS = {
            "microsoft", "google", "apple", "amazon", "paypal", "facebook",
            "netflix", "bankofamerica", "wellsfargo", "chase", "citibank",
            "linkedin", "twitter", "instagram", "whatsapp", "outlook",
            "office365", "adobe", "dropbox", "spotify", "ebay", "alibaba"
        }

        self.CHAR_SUBSTITUTIONS = {
            'o': ['0'],
            'i': ['1', 'l'],
            'l': ['1', 'i'],
            'e': ['3'],
            'a': ['4', '@'],
            's': ['5', '$'],
            't': ['7'],
            'b': ['8'],
            'g': ['9', 'q'],
            '0': ['o'],
            '1': ['i', 'l'],
            '3': ['e'],
            '4': ['a'],
            '5': ['s'],
            '7': ['t'],
            '8': ['b'],
            '9': ['g'],
        }

        self.COMMON_MISSPELLINGS = {
            'google': ['goggle', 'gooogle', 'g00gle', 'googl3', '9oogle'],
            'facebook': ['facebok', 'faceboook', 'faceb00k', 'faceb0ok', 'facebook'],
            'microsoft': ['micorsoft', 'micr0soft', 'm1crosoft', 'micros0ft', 'microsoft'],
            'paypal': ['paypa1', 'paypall', 'paypa1', 'payp4l', 'paypal'],
            'amazon': ['amazen', 'amaz0n', 'amaz0n', '4mazon', 'amaz0n'],
            'apple': ['app1e', 'appie', 'app1e', '4pple', '@pple'],
            'twitter': ['tw1tter', 'twitt3r', 'tw1tt3r', 'twiter'],
            'instagram': ['1nstagram', 'instagr4m', '1nstagr4m', 'instagran'],
            'whatsapp': ['whatsap', 'whats4pp', 'whats@pp', 'whatsappp'],
            'outlook': ['out1ook', 'outl00k', '0utlook', 'outlok'],
        }

        self.BRAND_VARIANTS = {}
        for brand in self.BRANDS:
            variants = self._generate_typo_variants(brand)
            self.BRAND_VARIANTS[brand] = variants

        suspicious_words = [
            "login","log in","password","pass","verify","verification",
            "reset","update","urgent","bank","account","security",
            "confirm","click","unlock","suspend","locked",
            "immediately","action required","suspended","billing","invoice"
        ]

        self.SUSPICIOUS_PATTERNS = [
            re.compile(r"\b" + re.escape(w) + r"\b", re.IGNORECASE)
            for w in suspicious_words
        ]

        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = 5.0
        self.resolver.timeout = 3.0
        self.mx_cache = {}

    def _generate_typo_variants(self, word):
        variants = set()
        variants.add(word.lower())
        
        word_lower = word.lower()
        for i, char in enumerate(word_lower):
            if char in self.CHAR_SUBSTITUTIONS:
                for sub in self.CHAR_SUBSTITUTIONS[char]:
                    variant = word_lower[:i] + sub + word_lower[i+1:]
                    variants.add(variant)
        
        if word_lower in self.COMMON_MISSPELLINGS:
            variants.update(self.COMMON_MISSPELLINGS[word_lower])
        
        variants.add(word_lower + "support")
        variants.add(word_lower + "security")
        variants.add(word_lower + "verify")
        variants.add(word_lower + "login")
        
        no_vowels = re.sub(r'[aeiou]', '', word_lower)
        if len(no_vowels) >= 3:
            variants.add(no_vowels)
        
        return variants

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
        return {"Rule1_Status": status, "Rule1_From_Email": f, "Rule1_Return_Email": r}

    # Rule 2: SPF and DKIM authentication check
    def rule2_auth(self, auth):
        a = str(auth or "").lower()
        spf = "NONE"; dkim = "NONE"
        if "spf=pass" in a: spf="PASS"
        elif "spf=fail" in a or "spf=hardfail" in a: spf="FAIL"
        if "dkim=pass" in a: dkim="PASS"
        elif "dkim=fail" in a: dkim="FAIL"
        result = "NORMAL" if (spf=="PASS" and dkim=="PASS") else "PHISHING"
        return {"Rule2_SPF": spf, "Rule2_DKIM": dkim, "Rule2_Result": result}

    # Rule 3: Domain risk assessment with enhanced brand impersonation
    def rule3_domain(self, from_h):
        def extract_email(v):
            try: return parseaddr(str(v))[1]
            except Exception:
                m = re.findall(r'[\w\.-]+@[\w\.-]+', str(v) or "")
                return m[0] if m else ""
        
        email_addr = (extract_email(from_h) or "").strip()
        if "@" not in email_addr:
            return {"Rule3_Risk_Score":60,"Rule3_Risk_Level":"High","Rule3_Domain":"","Rule3_Brand_Impersonation":None}
        
        domain = email_addr.split("@",1)[1].lower()
        score = 0
        brand_imp = None
        detection_type = ""
        
        try:
            ext = tldextract.extract(domain)
            domain_name = ext.domain.lower()  # Get the main domain part (before TLD)
            tld = ext.suffix.lower() if ext.suffix else ""
            tld_parts = tld.split(".") if tld else []
            
            # 1. Check for suspicious TLDs
            if any(part in self.SUSPICIOUS_TLDS for part in tld_parts): 
                score += 25
            
            # 2. Brand impersonation detection with multiple techniques
            
            common_legit = set()
            for brand in self.BRANDS:
                common_legit.update({f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.co", f"{brand}.edu"})
            
            if domain in common_legit:
                pass
            else:
                for brand in self.BRANDS:
                    if brand in domain_name:
                        brand_imp = brand
                        detection_type = "exact_substring"
                        score += 20
                        break
                
                if not brand_imp:
                    for brand, variants in self.BRAND_VARIANTS.items():
                        for variant in variants:
                            if variant in domain_name:
                                brand_imp = brand
                                detection_type = f"typo_variant ({variant})"
                                score += 25  # Higher score for typosquatting
                                break
                        if brand_imp:
                            break
                
                if not brand_imp:
                    for brand in self.BRANDS:
                        similarity = SequenceMatcher(None, brand, domain_name).ratio()
                        if 0.7 <= similarity < 1.0:  # 70% similarity threshold
                            # Additional check to avoid false positives
                            if len(domain_name) >= len(brand) * 0.6:  # At least 60% of brand length
                                brand_imp = brand
                                detection_type = f"fuzzy_match ({similarity:.2f})"
                                score += 30  # Highest score for clever impersonation
                                break
                
                if not brand_imp:
                    common_suffixes = ["support", "security", "verify", "login", "account", "service", "team", "help"]
                    for brand in self.BRANDS:
                        for suffix in common_suffixes:
                            if f"{brand}{suffix}" in domain_name or f"{brand}-{suffix}" in domain_name:
                                brand_imp = brand
                                detection_type = f"brand_with_suffix"
                                score += 22
                                break
                        if brand_imp:
                            break
            
        except Exception: 
            pass
        
        if not self._has_mx_records(domain): 
            score += 25
        
        brand_info = None
        if brand_imp:
            brand_info = f"{brand_imp} ({detection_type})" if detection_type else brand_imp
        
        risk = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
        return {"Rule3_Risk_Score":score,"Rule3_Risk_Level":risk,"Rule3_Domain":domain,"Rule3_Brand_Impersonation":brand_info}

    def _has_mx_records(self, domain):
        if not domain: return False
        if domain in self.mx_cache: return self.mx_cache[domain]
        try:
            answers = self.resolver.resolve(domain, "MX")
            ok = len(answers) > 0
        except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN,dns.resolver.NoNameservers):
            try:
                aans = self.resolver.resolve(domain, "A")
                ok = len(aans) >0
            except Exception: ok=False
        except Exception: ok=False
        self.mx_cache[domain]=ok
        return ok

    # Rule 4: Check if Message-ID exists
    def rule4_message_id(self,msg_id):
        mid=str(msg_id or "").strip()
        return {"Rule4_Message_ID":mid,"Rule4_Missing":(mid=="")}

  # Rule 5: Content analysis for suspicious words and link mismatches
def rule5_content(self, body_text, body_html):
    text = (body_text or "")[:200000]
    html = (body_html or "")[:200000]

    URL_RE = re.compile(r"https?://[^\s\"\'<>]+", re.IGNORECASE)

    def contains_suspicious(txt):
        for patt in self.SUSPICIOUS_PATTERNS:
            if patt.search(txt or ""):
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
        except Exception:
            pass
        return links

    def extract_links_from_text(t):
        try:
            return [(u, u) for u in URL_RE.findall(t or "")]
        except Exception:
            return []

    def check_mismatch(visible, actual):
        try:
            v = (visible or "").strip()
            a = (actual or "").strip()
            if not a:
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
    total=0; flagged=0
    low_risk=0; medium_risk=0; high_risk=0

    # Fields for CSV output including Source_IP
    fields=[
        "Filename","Subject","From","Return-Path","Authentication-Results",
        "Message-ID","Date","Source_IP", 
        "Rule1_Status","Rule1_From_Email","Rule1_Return_Email",
        "Rule2_SPF","Rule2_DKIM","Rule2_Result",
        "Rule3_Risk_Score","Rule3_Risk_Level","Rule3_Domain","Rule3_Brand_Impersonation",
        "Rule4_Message_ID","Rule4_Missing",
        "Rule5_Phishing","Rule5_Reasons","Rule5_Suspicious_Words","Rule5_Link_Mismatch",
        "Total_Risk_Score"
    ]

    try:
        with open(INPUT_CSV,"r",encoding="utf-8") as inp, \
             open(OUTPUT_CSV,"w",newline="",encoding="utf-8") as out:

            reader = csv.DictReader(inp)
            writer = csv.DictWriter(out, fieldnames=fields)
            writer.writeheader()

            for idx, row in enumerate(reader, start=1):
                total+=1
                print(f"[PROGRESS] Now at email #{idx}")

                filename = row.get("Filename","") or f"row_{idx}"
                subject = row.get("Subject","")
                from_h = row.get("From","")
                source_ip = row.get("Source_IP","")  # <- read Source_IP from CSV

                r1 = det.rule1_from_return(from_h,row.get("Return-Path",""))
                r2 = det.rule2_auth(row.get("Authentication-Results",""))
                r3 = det.rule3_domain(from_h)
                r4 = det.rule4_message_id(row.get("Message-ID",""))
                r5 = det.rule5_content(row.get("Body_Text",""), row.get("Body_HTML",""))

                # ===== Calculate total risk score =====
                risk_score=0
                if r1["Rule1_Status"]=="DIFFER": risk_score+=15
                if r2["Rule2_Result"]=="PHISHING": risk_score+=20
                if r3["Rule3_Risk_Level"]=="High": risk_score+=30
                elif r3["Rule3_Risk_Level"]=="Medium": risk_score+=15
                if r4["Rule4_Missing"]: risk_score+=5
                if r5["Rule5_Phishing"]: risk_score+=30

                # Count emails by risk level
                if risk_score<30: low_risk+=1
                elif risk_score<=60: medium_risk+=1
                else: high_risk+=1

                # Count flagged phishing emails
                is_phishing = bool(r5.get("Rule5_Phishing", False)) or \
                              (r2.get("Rule2_Result")=="PHISHING") or \
                              (r3.get("Rule3_Risk_Level")=="High")
                if is_phishing: flagged+=1

                out_row = {
                    "Filename":filename,
                    "Subject":subject,
                    "From":from_h,
                    "Return-Path":row.get("Return-Path",""),
                    "Authentication-Results":row.get("Authentication-Results",""),
                    "Message-ID":row.get("Message-ID",""),
                    "Date":row.get("Date",""),
                    "Source_IP": source_ip,  # <- add IP here
                    **r1, **r2, **r3, **r4, **r5,
                    "Total_Risk_Score":risk_score
                }

                writer.writerow({k: out_row.get(k,"") for k in fields})

    except FileNotFoundError as e:
        print(f"[ERROR] Input file not found: {e}")
        return
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        return

    # ===== Color-coded summary =====
    GREEN="\033[92m"; ORANGE="\033[93m"; RED="\033[91m"; RESET="\033[0m"
    print("\n===== PHISHING RISK SUMMARY =====")
    print(f"{GREEN}🟢 LOW RISK    (<30):    {low_risk} emails{RESET}")
    print(f"{ORANGE}🟠 MEDIUM RISK (30–60):  {medium_risk} emails{RESET}")
    print(f"{RED}🔴 HIGH RISK   (>60):    {high_risk} emails{RESET}")
    print("================================")
    print(f"Total processed emails: {total}. Flagged as phishing: {flagged}")
    print(f"Results saved to: {OUTPUT_CSV}")

if __name__=="__main__":
    main()
