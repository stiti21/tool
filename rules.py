#!/usr/bin/env python3
# coding: utf-8

import csv
import re
from email.utils import parseaddr
import dns.resolver
import tldextract
from bs4 import BeautifulSoup
from difflib import SequenceMatcher

INPUT_CSV = "/home/kali/tool/csv/email.csv"
OUTPUT_CSV = "/home/kali/tool/csv/test.csv"

csv.field_size_limit(10000000)

class PhishingDetector:
    def __init__(self):
        self.SUSPICIOUS_TLDS = {
            "top","xyz","zip","click","quest","shop","online",
            "ink","center","group","io","club","site"
        }

        self.BRANDS = {
            "microsoft","google","apple","amazon","paypal","facebook",
            "netflix","bankofamerica","wellsfargo","chase","citibank",
            "linkedin","twitter","instagram","whatsapp","outlook",
            "office365","adobe","dropbox","spotify","ebay","alibaba"
        }

        self.CHAR_SUBSTITUTIONS = {
            'o':['0'],'i':['1','l'],'l':['1','i'],'e':['3'],
            'a':['4','@'],'s':['5','$'],'t':['7'],'b':['8'],
            'g':['9','q'],'0':['o'],'1':['i','l'],'3':['e'],
            '4':['a'],'5':['s'],'7':['t'],'8':['b'],'9':['g']
        }

        self.COMMON_MISSPELLINGS = {
            'google':['goggle','gooogle','g00gle','googl3','9oogle'],
            'facebook':['facebok','faceboook','faceb00k','faceb0ok'],
            'microsoft':['micorsoft','micr0soft','m1crosoft','micros0ft'],
            'paypal':['paypa1','paypall','payp4l'],
            'amazon':['amazen','amaz0n','4mazon'],
            'apple':['app1e','appie','4pple','@pple'],
            'twitter':['tw1tter','twitt3r','twiter'],
            'instagram':['1nstagram','instagr4m','instagran'],
            'whatsapp':['whatsap','whats4pp','whats@pp','whatsappp'],
            'outlook':['out1ook','outl00k','0utlook','outlok'],
        }

        self.BRAND_VARIANTS = {}
        for brand in self.BRANDS:
            self.BRAND_VARIANTS[brand] = self._generate_typo_variants(brand)

        suspicious_words = [
            "login","password","verify","reset","update","urgent",
            "bank","account","security","confirm","click","unlock",
            "suspend","locked","immediately","action required",
            "billing","invoice"
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
        w = word.lower()
        variants.add(w)

        for i, c in enumerate(w):
            if c in self.CHAR_SUBSTITUTIONS:
                for sub in self.CHAR_SUBSTITUTIONS[c]:
                    variants.add(w[:i] + sub + w[i+1:])

        if w in self.COMMON_MISSPELLINGS:
            variants.update(self.COMMON_MISSPELLINGS[w])

        for s in ["support","security","verify","login"]:
            variants.add(w + s)

        no_vowels = re.sub(r'[aeiou]', '', w)
        if len(no_vowels) >= 3:
            variants.add(no_vowels)

        return variants

    def rule1_from_return(self, from_h, return_h):
        def get_email(v):
            try:
                return parseaddr(str(v))[1].lower()
            except:
                m = re.findall(r'[\w\.-]+@[\w\.-]+', str(v) or "")
                return m[0].lower() if m else ""
        f = get_email(from_h)
        r = get_email(return_h)
        status = "MATCH" if f and f == r else "DIFFER"
        return {"Rule1_Status":status,"Rule1_From_Email":f,"Rule1_Return_Email":r}

    def rule2_auth(self, auth):
        a = str(auth or "").lower()
        spf="NONE"; dkim="NONE"
        if "spf=pass" in a: spf="PASS"
        elif "spf=fail" in a or "spf=hardfail" in a: spf="FAIL"
        if "dkim=pass" in a: dkim="PASS"
        elif "dkim=fail" in a: dkim="FAIL"
        res = "NORMAL" if spf=="PASS" and dkim=="PASS" else "PHISHING"
        return {"Rule2_SPF":spf,"Rule2_DKIM":dkim,"Rule2_Result":res}

    def rule3_domain(self, from_h):
        email = parseaddr(str(from_h))[1]
        if "@" not in email:
            return {"Rule3_Risk_Score":60,"Rule3_Risk_Level":"High","Rule3_Domain":"","Rule3_Brand_Impersonation":None}

        domain = email.split("@",1)[1].lower()
        score = 0
        brand_imp=None
        dtype=""

        try:
            ext = tldextract.extract(domain)
            name = ext.domain.lower()
            tld_parts = ext.suffix.split(".") if ext.suffix else []

            if any(p in self.SUSPICIOUS_TLDS for p in tld_parts):
                score += 25

            for b in self.BRANDS:
                if b in name:
                    brand_imp=b; dtype="substring"; score+=20; break

            if not brand_imp:
                for b,vars in self.BRAND_VARIANTS.items():
                    for v in vars:
                        if v in name:
                            brand_imp=b; dtype=f"typo ({v})"; score+=25; break
                    if brand_imp: break

            if not brand_imp:
                for b in self.BRANDS:
                    sim = SequenceMatcher(None,b,name).ratio()
                    if 0.7<=sim<1.0:
                        brand_imp=b; dtype=f"fuzzy ({sim:.2f})"; score+=30; break
        except:
            pass

        if not self._has_mx_records(domain):
            score+=25

        info = f"{brand_imp} ({dtype})" if brand_imp else None
        level = "High" if score>=60 else "Medium" if score>=30 else "Low"
        return {"Rule3_Risk_Score":score,"Rule3_Risk_Level":level,"Rule3_Domain":domain,"Rule3_Brand_Impersonation":info}

    def _has_mx_records(self, domain):
        if not domain: return False
        if domain in self.mx_cache: return self.mx_cache[domain]
        try:
            ok = len(self.resolver.resolve(domain,"MX"))>0
        except:
            ok=False
        self.mx_cache[domain]=ok
        return ok

    def rule4_message_id(self, msg_id):
        mid=str(msg_id or "").strip()
        return {"Rule4_Message_ID":mid,"Rule4_Missing":mid==""}

    def rule5_content(self, body_text, body_html):
        text = body_text or ""
        html = body_html or ""

        def contains(txt):
            return any(p.search(txt) for p in self.SUSPICIOUS_PATTERNS)

        links=[]
        try:
            soup = BeautifulSoup(html,"html.parser")
            for a in soup.find_all("a",href=True):
                links.append((a.get_text(strip=True),a["href"]))
        except:
            pass

        mismatch=False
        for v,a in links:
            if v and a and v.lower()!=a.lower():
                mismatch=True; break

        phish = contains(text+" "+html) or mismatch
        return {
            "Rule5_Phishing":phish,
            "Rule5_Reasons":"suspicious_words" if phish else "clean",
            "Rule5_Suspicious_Words":contains(text+" "+html),
            "Rule5_Link_Mismatch":mismatch
        }

def main():
    det = PhishingDetector()

    fields=[
        "Filename","Subject","From","Return-Path","Authentication-Results",
        "Message-ID","Date",
        "Rule1_Status","Rule1_From_Email","Rule1_Return_Email",
        "Rule2_SPF","Rule2_DKIM","Rule2_Result",
        "Rule3_Risk_Score","Rule3_Risk_Level","Rule3_Domain","Rule3_Brand_Impersonation",
        "Rule4_Message_ID","Rule4_Missing",
        "Rule5_Phishing","Rule5_Reasons","Rule5_Suspicious_Words","Rule5_Link_Mismatch",
        "Total_Risk_Score"
    ]

    with open(INPUT_CSV,"r",encoding="utf-8") as inp, \
         open(OUTPUT_CSV,"w",newline="",encoding="utf-8") as out:

        reader = csv.DictReader(inp)
        writer = csv.DictWriter(out,fieldnames=fields)
        writer.writeheader()

        for i,row in enumerate(reader,1):
            print(f"[PROGRESS] Now at email #{i}")

            r1 = det.rule1_from_return(row.get("From",""),row.get("Return-Path",""))
            r2 = det.rule2_auth(row.get("Authentication-Results",""))
            r3 = det.rule3_domain(row.get("From",""))
            r4 = det.rule4_message_id(row.get("Message-ID",""))
            r5 = det.rule5_content(row.get("Body_Text",""),row.get("Body_HTML",""))

            score=0
            if r1["Rule1_Status"]=="DIFFER": score+=15
            if r2["Rule2_Result"]=="PHISHING": score+=20
            if r3["Rule3_Risk_Level"]=="High": score+=30
            elif r3["Rule3_Risk_Level"]=="Medium": score+=15
            if r4["Rule4_Missing"]: score+=5
            if r5["Rule5_Phishing"]: score+=30

            out_row={
                "Filename":row.get("Filename",""),
                "Subject":row.get("Subject",""),
                "From":row.get("From",""),
                "Return-Path":row.get("Return-Path",""),
                "Authentication-Results":row.get("Authentication-Results",""),
                "Message-ID":row.get("Message-ID",""),
                "Date":row.get("Date",""),
                **r1,**r2,**r3,**r4,**r5,
                "Total_Risk_Score":score
            }

            writer.writerow({k:out_row.get(k,"") for k in fields})

    print(f"\nDone ✔ Results saved to: {OUTPUT_CSV}")

if __name__=="__main__":
    main()
