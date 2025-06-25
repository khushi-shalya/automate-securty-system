import requests
import socket
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fpdf import FPDF

def get_subdomains_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = set()
    try:
        data = requests.get(url, timeout=15).json()
        for entry in data:
            for name in entry['name_value'].split('\n'):
                subs.add(name.strip())
    except:
        pass
    return {s for s in subs if s.endswith(domain)}

def get_subdomains_threatcrowd(domain):
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    try:
        r = requests.get(url, timeout=15).json()
        return set(r.get('subdomains', []))
    except:
        return set()

def dns_exists(host):
    try:
        socket.gethostbyname(host)
        return True
    except:
        return False

def is_live_http(host):
    session = requests.Session()
    retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[500,502,503,504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    for scheme in ('https://', 'http://'):
        try:
            r = session.get(scheme + host, timeout=5, allow_redirects=True)
            if r.status_code < 400:
                return scheme + host
        except:
            continue
    return None

def create_pdf_report(domain, total, live_links):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14)
    pdf.cell(200, 10, txt=f"Subdomain Scan Report for: {domain}", ln=True, align='C')
    
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Total Subdomains Collected: {total}", ln=True)
    pdf.cell(200, 10, txt=f"Live Subdomains Found: {len(live_links)}", ln=True)

    pdf.ln(5)
    pdf.set_font("Arial", size=10)
    for link in sorted(live_links):
        pdf.multi_cell(0, 8, txt=link)

    output_file = f"{domain}_subdomain_report.pdf"
    pdf.output(output_file)
    print(f"\n✅ PDF report saved as: {output_file}")

def main():
    domain = input("Enter target domain (e.g. example.com): ").strip()

    print("\n[*] Collecting subdomains from crt.sh and ThreatCrowd...")
    subs = get_subdomains_crtsh(domain) | get_subdomains_threatcrowd(domain)
    subs = {s for s in subs if s.endswith(domain)}
    print(f"[+] {len(subs)} total subdomains found")

    print("[*] Filtering valid DNS...")
    valid = [s for s in subs if dns_exists(s)]
    print(f"[+] {len(valid)} passed DNS check")

    print("[*] Checking live status over HTTP/HTTPS...")
    live = []
    with ThreadPoolExecutor(max_workers=30) as exe:
        for res in exe.map(is_live_http, valid):
            if res:
                print("✅ Live:", res)
                live.append(res)

    print(f"\n[+] Scan complete. {len(live)} live subdomains found")

    # Only PDF output
    create_pdf_report(domain, len(subs), live)

if __name__ == "__main__":
    main()
