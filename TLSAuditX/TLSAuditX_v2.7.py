
import ssl
import socket
import tkinter as tk # These are GUI-only imports. REMOVE or COMMENT them.
from tkinter import messagebox, scrolledtext, filedialog # These are GUI-only imports. REMOVE or COMMENT them.
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Keep: This is backend logic
def clean_domain(domain):
    domain = domain.strip().replace("https://", "").replace("http://", "")
    return domain.split("/")[0]

#  Keep: Core function to fetch certificate
def fetch_tls_cert(domain):
    domain = clean_domain(domain)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {"error": str(e)}

# Keep: Function to analyze certificate
def analyze_cert(cert):
    if "error" in cert:
        return f"❌ Error: {cert['error']}"

    output = []
    subject = dict(x[0] for x in cert['subject'])
    issuer = dict(x[0] for x in cert['issuer'])

    output.append("📄 TLS Certificate Details:")
    output.append(f"🔐 Subject CN : {subject.get('commonName', 'N/A')}")
    output.append(f"🏢 Issuer     : {issuer.get('organizationName', 'N/A')} ({issuer.get('commonName', 'N/A')})")
    output.append(f"📅 Valid From : {cert.get('notBefore')}")
    output.append(f"📅 Valid To   : {cert.get('notAfter')}")

    try:
        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry - datetime.utcnow()).days
        output.append(f"⏳ Expires In : {days_left} days")
    except:
        pass

    san = cert.get('subjectAltName', [])
    san_list = [x[1] for x in san]
    output.append(f"🌐 SANs       : {', '.join(san_list)}")

    return "\n".join(output)

# GUI Function: Remove or comment out if React is used
def on_scan():
    domain = entry.get().strip()
    result_box.delete(1.0, tk.END)
    if not domain:
        messagebox.showerror("Input Error", "Please enter a domain name.")
        return

    cleaned = clean_domain(domain)
    result_box.insert(tk.END, f"🔍 Fetching certificate for {cleaned}...\n\n")
    root.update()

    cert = fetch_tls_cert(cleaned)
    result = analyze_cert(cert)
    result_box.insert(tk.END, result)

# Keep: Just separate the logic, and allow data and path to be passed
def save_report_pdf():
    data = result_box.get("1.0", tk.END).strip()
    if not data:
        messagebox.showwarning("Empty", "No data to save.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".pdf", title="Save PDF Report", filetypes=[("PDF Files", "*.pdf")])
    if not file_path:
        return

    try:
        c = canvas.Canvas(file_path, pagesize=letter)
        width, height = letter
        lines = data.split("\n")
        y = height - 40

        c.setFont("Courier", 10)
        c.drawString(40, y, "TLSAuditX - TLS Certificate PDF Report")
        y -= 30

        from textwrap import wrap
        max_width = 95
        for line in lines:
            wrapped_lines = wrap(line, width=max_width)
            for wrap_line in wrapped_lines:
                if y < 50:
                    c.showPage()
                    y = height - 40
                    c.setFont("Courier", 10)
                c.drawString(40, y, wrap_line)
                y -= 15

        c.save()
        messagebox.showinfo("Saved", f"✅ PDF report saved:\n{file_path}")

    except Exception as e:
        messagebox.showerror("Error", f"PDF save failed:\n{str(e)}")

#GUI-dependent: Should be removed when building API + React frontend
def load_and_scan_file():
    file_path = filedialog.askopenfilename(title="Select Domain List", filetypes=[("Text Files", "*.txt")])
    if not file_path:
        return

    result_box.delete(1.0, tk.END)
    result_box.insert(tk.END, f"📂 Loaded file: {file_path}\n\n")

    try:
        with open(file_path, "r") as f:
            domains = [line.strip() for line in f if line.strip()]

        with open("tlsauditx_log.txt", "w", encoding="utf-8") as logf:
            for domain in domains:
                cleaned = clean_domain(domain)
                result_box.insert(tk.END, f"\n🔍 Fetching cert for: {cleaned}\n")
                root.update()

                cert = fetch_tls_cert(cleaned)
                result = analyze_cert(cert)
                result_box.insert(tk.END, result + "\n" + "-"*60 + "\n")
                root.update()

                if "error" in cert:
                    logf.write(f"{cleaned} => ❌ {cert['error']}\n")
                else:
                    logf.write(f"{cleaned} => ✅ Success\n")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to read file:\n{str(e)}")

# GUI-dependent: Should be removed when building API + React frontend
root = tk.Tk()
root.title("TLSAuditX v2.3 - TLS Certificate Analyzer")
root.geometry("750x550")
root.config(bg="#0f111a")

font_label = ("Consolas", 12)
font_entry = ("Consolas", 12)
font_btn = ("Consolas", 11, "bold")
fg_color = "white"
bg_entry = "#1e1e1e"
btn_color = "#007acc"

tk.Label(root, text="Enter Domain:", fg=fg_color, bg="#0f111a", font=font_label).pack(pady=10)
entry = tk.Entry(root, width=40, font=font_entry, bg=bg_entry, fg=fg_color, insertbackground=fg_color, relief="flat")
entry.pack()

btn_frame = tk.Frame(root, bg="#0f111a")
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="🎯 Fetch Single Domain", command=on_scan, bg=btn_color, fg=fg_color, font=font_btn, padx=10).pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="📂 Load List & Scan", command=load_and_scan_file, bg="#f39c12", fg=fg_color, font=font_btn, padx=10).pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="🖨 Export as PDF", command=save_report_pdf, bg="#9b59b6", fg=fg_color, font=font_btn, padx=10).pack(side=tk.LEFT, padx=5)

result_box = scrolledtext.ScrolledText(root, width=90, height=20, font=("Courier New", 10), bg="#121212", fg="#00ff99", insertbackground="white", relief="flat")
result_box.pack(pady=10)

root.mainloop()
