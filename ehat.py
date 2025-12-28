import os

def show_banner():

print("\033[91m")

print(r"""

███████╗██╗  ██╗ █████╗ ████████╗

██╔════╝██║  ██║██╔══██╗╚══██╔══╝

█████╗  ███████║███████║   ██║

██╔══╝  ██╔══██║██╔══██║   ██║

███████╗██║  ██║██║  ██║   ██║

╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝

EHAT - Email Header Analysis Tool

Phishing Detection & Forensic Analysis

""")

print("\033[0m")

def main():

show_banner()



print("[*] Step 1: Extracting email headers & bodies...")

os.system("python3 testmain.py")



print("[*] Step 2: Running phishing detection rules...")

os.system("python3 rules.py")



print("[*] Step 3: Generating forensic PDF report...")

os.system("python3 forensic_report.py")



print("\n[✔] EHAT finished successfully.")

if name == "main":

main()
