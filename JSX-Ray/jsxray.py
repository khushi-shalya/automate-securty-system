#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import json
import os
import argparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

url_pattern = re.compile(r'https?:\/\/[^\s\'"<>]+|\/[a-zA-Z0-9\/\-_?=&%\.]+')
key_pattern = re.compile(r'(key|token|auth|password|secret)\s*[:=]\s*["\']?[\w\-]{8,}')
risky_keywords = ['admin', 'debug', 'token', 'auth', 'key', 'password', 'secret']

def extract_js_links(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    script_tags = soup.find_all("script", src=True)
    js_links = set()
    for tag in script_tags:
        src = tag['src']
        full_url = urljoin(base_url, src)
        if urlparse(full_url).netloc == urlparse(base_url).netloc and not any(cdn in full_url for cdn in ['googleapis', 'cloudflare', 'cdnjs']):
            js_links.add(full_url)
    return list(js_links)

def scan_js(js_url, save_raw=False):
    findings = {"urls": [], "keywords": [], "secrets": []}
    try:
        r = requests.get(js_url, timeout=10)
        r.raise_for_status()
        content = r.text

        if save_raw:
            fname = js_url.split("/")[-1].split("?")[0]
            os.makedirs("raw_js", exist_ok=True)
            with open(f"raw_js/{fname}", "w", encoding="utf-8", errors="ignore") as f:
                f.write(content)

        findings["urls"] = list(set(url_pattern.findall(content)))
        findings["keywords"] = [kw for kw in risky_keywords if kw in content]
        findings["secrets"] = key_pattern.findall(content)
        
        if findings["urls"] or findings["keywords"] or findings["secrets"]:
            print(f"{Fore.CYAN}[+] {js_url}{Style.RESET_ALL}")
            if findings["urls"]:
                print(f"  {Fore.YELLOW}Endpoints:{Style.RESET_ALL}")
                for u in findings["urls"]:
                    print(f"    - {u}")
            if findings["keywords"]:
                print(f"  {Fore.RED}Keywords:{Style.RESET_ALL}")
                for k in findings["keywords"]:
                    print(f"    - {k}")
            if findings["secrets"]:
                print(f"  {Fore.MAGENTA}Secrets:{Style.RESET_ALL}")
                for s in findings["secrets"]:
                    print(f"    - {s}")

        return js_url, findings
    except Exception as e:
        print(f"{Fore.RED}[-] Error fetching {js_url}: {e}{Style.RESET_ALL}")
        return js_url, None

def process_single_url(url, threads, save_js, output_file):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        js_files = extract_js_links(url, r.text)
        print(f"\n{Fore.GREEN}[+] Found {len(js_files)} internal JS files from {url}{Style.RESET_ALL}\n")

        report = {}
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(scan_js, js, save_js) for js in js_files]
            for future in futures:
                js_url, result = future.result()
                if result:
                    report[js_url] = result

        if report:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, "w") as f:
                json.dump(report, f, indent=4)
            print(f"\n{Fore.GREEN}[✓] Results saved to {output_file}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] No significant findings for {url}.{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[-] Error processing {url}: {e}{Style.RESET_ALL}")

def process_js_url_list(js_list_path, threads, save_js, output_file):
    with open(js_list_path, "r") as f:
        js_urls = [line.strip() for line in f if line.strip()]
    
    print(f"\n{Fore.GREEN}[+] Scanning {len(js_urls)} JS URLs from list...{Style.RESET_ALL}")
    
    report = {}
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_js, js_url, save_js) for js_url in js_urls]
        for future in futures:
            js_url, result = future.result()
            if result:
                report[js_url] = result

    if report:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(report, f, indent=4)
        print(f"\n{Fore.GREEN}[✓] JS URL scan results saved to {output_file}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}[!] No significant findings in provided JS URLs.{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="JSX-Ray - Scan JavaScript files for endpoints and secrets")
    parser.add_argument("--url", help="Target base URL (e.g., https://example.com)")
    parser.add_argument("--list", help="File containing list of domains (one per line)")
    parser.add_argument("--js-list", help="File containing raw JS file URLs (one per line)")
    parser.add_argument("--output", default="outputs/results.json", help="Output file or folder")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("--save-js", action="store_true", help="Save raw JS files to raw_js/")
    args = parser.parse_args()

    if not args.url and not args.list and not args.js_list:
        parser.error("You must provide either --url, --list, or --js-list.")

    if args.url:
        process_single_url(args.url, args.threads, args.save_js, args.output)

    if args.list:
        if os.path.exists(args.output) and not os.path.isdir(args.output):
            print(f"{Fore.RED}[-] Error: {args.output} exists and is not a directory!{Style.RESET_ALL}")
            return
        os.makedirs(args.output, exist_ok=True)
        with open(args.list, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
        for domain in domains:
            domain_name = urlparse(domain).netloc.replace(":", "_")
            out_file = os.path.join(args.output, f"{domain_name}.json")
            process_single_url(domain, args.threads, args.save_js, out_file)

    if args.js_list:
        process_js_url_list(args.js_list, args.threads, args.save_js, args.output)

if __name__ == "__main__":
    main()
