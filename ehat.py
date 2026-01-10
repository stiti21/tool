import os

# File to save all outputs from the scripts
OUTPUT_LOG = "ehat_output.log"

def show_banner():
    """Displays the EHAT banner in color"""
    print("\033[96m")
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
    print("\033[0m")  # Reset terminal color


def run_silently(command):
    """
    Runs a command silently and appends all output (stdout + stderr) to OUTPUT_LOG
    """
    with open(OUTPUT_LOG, "a") as f:
        f.write(f"\n--- Running: {command} ---\n")
        os.system(f"{command} >> {OUTPUT_LOG} 2>&1")


def main():
    # Clear previous log at the start of each run
    open(OUTPUT_LOG, "w").close()

    show_banner()

    print("[*] Step 1: Extracting email headers & bodies...")
    run_silently("python3 withoutip.py")

    print("[*] Step 2: Running phishing detection rules...")
    run_silently("python3 rule.py")

    print("[*] Step 3: Generating forensic PDF report...")
    run_silently("python3 report.py")

    print("\n[✔] EHAT finished successfully.")
    print(f"All script outputs have been saved to {OUTPUT_LOG}")


if __name__ == "__main__":
    main()
