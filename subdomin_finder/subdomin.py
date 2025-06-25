import subprocess
import os
from fpdf import FPDF

def run_sublist3r(domain):
    print("[*] Running Sublist3r...")
    output_file = "sublist3r_output.txt"
    try:
        subprocess.run(["sublist3r", "-d", domain, "-o", output_file], check=True)
    except Exception as e:
        print(f"[!] Sublist3r encountered an error but will continue: {e}")
    return output_file

def run_knockpy(domain):
    print("[*] Running Knockpy...")
    try:
        subprocess.run(["knockpy", "-d", domain], check=True)
    except Exception as e:
        print(f"[!] Knockpy encountered an error but will continue: {e}")
    return f"knockpy/results/{domain}.csv"

def extract_subdomains_from_txt(filename):
    subdomains = set()
    if os.path.exists(filename):
        with open(filename, "r") as file:
            for line in file:
                sub = line.strip()
                if sub:
                    subdomains.add(sub)
    return subdomains

def extract_subdomains_from_csv(csv_file):
    subdomains = set()
    if os.path.exists(csv_file):
        with open(csv_file, "r") as file:
            next(file)  # Skip header
            for line in file:
                parts = line.strip().split(",")
                if parts:
                    subdomains.add(parts[0])
    return subdomains

def save_report_pdf(domains, filename):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Combined Subdomain Report", ln=True, align='C')
    pdf.ln(10)

    for domain in domains:
        pdf.cell(200, 10, txt=domain, ln=True)

    pdf.output(filename)
    print(f"[+] PDF saved as: {filename}")

def main():
    domain = input("Enter a domain (e.g., example.com): ").strip()
    if domain.startswith("http"):
        domain = domain.replace("https://", "").replace("http://", "").strip("/")

    sublist3r_file = run_sublist3r(domain)
    knockpy_file = run_knockpy(domain)

    sublist3r_domains = extract_subdomains_from_txt(sublist3r_file)
    knockpy_domains = extract_subdomains_from_csv(knockpy_file)

    all_domains = sorted(sublist3r_domains.union(knockpy_domains))

    if not all_domains:
        print("[!] No subdomains found.")
        return

    pdf_name = f"{domain}_subdomain_report.pdf"
    save_report_pdf(all_domains, pdf_name)


    if os.path.exists(sublist3r_file):
        os.remove(sublist3r_file)
    if os.path.exists(knockpy_file):
        os.remove(knockpy_file)

if __name__ == "__main__":
    main()
