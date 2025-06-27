import requests
import threading
import queue
import argparse
import os
from urllib.parse import urljoin
from pathlib import Path

print_lock = threading.Lock()
output_lock = threading.Lock()

# Get Downloads folder path
downloads_folder = str(Path.home() / "Downloads")

def dir_buster(target_url, word_q, extensions, status_filter, timeout, output_file):
    while not word_q.empty():
        word = word_q.get()
        paths = [word]

        for ext in extensions:
            if ext and not word.endswith(ext):
                paths.append(f"{word}{ext}")

        for path in paths:
            url = urljoin(target_url, path)
            try:
                response = requests.get(url, timeout=timeout)
                status = response.status_code
                line = f"[{status}] {url}"

                if str(status) in status_filter:
                    with print_lock:
                        print(line)

                    if output_file:
                        with output_lock:
                            with open(output_file, "a") as out:
                                out.write(line + "\n")
            except requests.RequestException:
                continue

        word_q.task_done()

def main():
    parser = argparse.ArgumentParser(description="Advanced Directory Bursting Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com/)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-s", "--status", default="200,204,301,302,403", help="Comma-separated status codes to show")
    parser.add_argument("-to", "--timeout", type=int, default=5, help="Request timeout in seconds")
    parser.add_argument("-o", "--output", help="Output file name to save results (saved in Downloads folder)")
    parser.add_argument("-e", "--extensions", help="Comma-separated list of file extensions (e.g., php,env,sql)")

    args = parser.parse_args()

    target_url = args.url
    if not target_url.endswith("/"):
        target_url += "/"

    try:
        with open(args.wordlist, "r") as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[!] Wordlist not found.")
        return

    word_q = queue.Queue()
    for word in words:
        word_q.put(word)

    status_filter = args.status.split(",")
    extensions = args.extensions.split(",") if args.extensions else [""]
    output_path = os.path.join(downloads_folder, args.output) if args.output else None

    if output_path and os.path.exists(output_path):
        os.remove(output_path)  # Clear previous content

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(
            target=dir_buster,
            args=(target_url, word_q, extensions, status_filter, args.timeout, output_path)
        )
        t.daemon = True
        threads.append(t)
        t.start()

    word_q.join()

    if output_path:
        print(f"\n[✓] Results saved to: {output_path}")

if __name__ == "__main__":
    main()
