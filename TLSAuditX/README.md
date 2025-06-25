# 🔐 TLSAuditX v2.7 - GUI TLS Certificate Analyzer & PDF Reporter

TLSAuditX is a powerful, user-friendly GUI tool that helps you fetch and analyze TLS/SSL certificates for a single domain or a bulk list of domains. Built for security researchers, pentesters, and sysadmins, it simplifies the process of auditing certificates and exporting professional reports.

---

## 🛠 Features

- ✅ Analyze TLS certificates of any domain  
- 📂 Load a list of domains from a `.txt` file  
- 🧹 Automatically cleans domain input (removes protocols/paths)  
- 📄 Export full certificate info to a PDF file  
- 📝 Save scan log with ✅ Success / ❌ Failure status per domain  
- 🖥 Clean dark-themed GUI built with `tkinter`  
- 📦 No internet required after installation  

---

## 🔎 What It Shows

- **Subject CN** – Common Name of the cert  
- **Issuer** – Certificate Authority (CA)  
- **Valid From / To** – Validity window  
- **Days Until Expiry** – Expiration countdown  
- **SANs** – Subject Alternative Names  

---

## 📸 GUI Preview



---

## 🚀 How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# Run the GUI
python TLSAuditX_v2.7.py
