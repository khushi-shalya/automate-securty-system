#!/usr/bin/python3

import socket
import threading
from queue import Queue
import time

# Colors
GREEN = "\033[92m"
RED = "\033[91m"      # <-- This was missing
CYAN = "\033[96m"
RESET = "\033[0m"

print_lock = threading.Lock()
open_ports = []
queue = Queue()

# ------------------------------------------
# Function to scan one port and detect status
# ------------------------------------------
def scan_port(port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        try:
            banner = s.recv(1024).decode(errors='ignore').strip()
        except:
            banner = "No banner"
        with print_lock:
            print(f"{GREEN}[+] Open Port: {port} - {banner}{RESET}")
            open_ports.append((port, banner))
        s.close()
    except:
        pass  # Ignore closed or filtered ports silently

# Thread worker
def threader():
    while True:
        port = queue.get()
        scan_port(port)
        queue.task_done()

# ------------------------------
# Ask user for input
# ------------------------------
print(f"{CYAN}Welcome to the Advanced Port Scanner!{RESET}")

hostname = input("Enter website or IP to scan (e.g., example.com or 192.168.1.1): ").strip()

try:
    ip = socket.gethostbyname(hostname)
    print(f"{CYAN}Resolved {hostname} to {ip}{RESET}")
except socket.gaierror:
    print(f"{RED}Could not resolve hostname: {hostname}{RESET}")
    exit(1)

port_input = input("Enter port range (e.g., 20-1000 or leave blank for full range): ").strip()
if port_input:
    try:
        start_port, end_port = map(int, port_input.split("-"))
    except:
        print(f"{RED}Invalid port range format. Use format: start-end (e.g., 20-1000).{RESET}")
        exit(1)
else:
    start_port, end_port = 1, 65535

if start_port < 1 or end_port > 65535 or start_port > end_port:
    print(f"{RED}Invalid port range. Ports must be 1–65535 and START <= END.{RESET}")
    exit(1)

# ------------------------
# Start scanning
# ------------------------
print(f"{CYAN}Scanning {ip} ({hostname}) from port {start_port} to {end_port}...{RESET}")
start_time = time.time()

num_threads = 100
for _ in range(num_threads):
    t = threading.Thread(target=threader, daemon=True)
    t.start()

for port in range(start_port, end_port + 1):
    queue.put(port)

queue.join()

# ------------------------
# Final Summary: Only Open Ports
# ------------------------
print(f"\n{CYAN}Scan completed in {time.time() - start_time:.2f} seconds.{RESET}")
if open_ports:
    print(f"{GREEN}Open Ports Found: {len(open_ports)}{RESET}")
    for port, banner in open_ports:
        print(f"{GREEN}- Port {port}: {banner}{RESET}")
else:
    print(f"{RED}No open ports found.{RESET}")
