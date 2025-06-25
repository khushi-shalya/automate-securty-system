# 🕵️ IP Extractor & Classifier

A simple Python script for bug bounty hunters, red teamers, and recon enthusiasts that:

- Extracts IP addresses (both public and private) from domains/subdomains
- Classifies them as Public or Private/Bogon
- Fetches IP-related information (ISP, ASN, Location) using the ipinfo.io API

---

## 📦 Features

- ✅ Extract all IPs associated with a domain
- ✅ Identify whether IPs are Public or Private
- ✅ Query `ipinfo.io` for detailed public IP data
- ✅ Lightweight & CLI-friendly
- ✅ Perfect for Recon, OSINT, and Internal Pentesting

---

## 🚀 Usage

### 1. Clone the repo

```bash
git clone https://github.com/utkarsh-404/IP-Extractor.git
cd IP-Extractor
````

### 2. Install requirements

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not provided, install manually:

```bash
pip install requests
```

### 3. Run the script

```bash
python main.py
```

You’ll be prompted to enter a domain (e.g. `example.com`) and see something like:

```
Domain: example.com
  -> IP: 93.184.216.34 (Public)
     - Org: AS15133 Edgecast Inc.
     - Location: Los Angeles, California, US
```

---

## 🔧 Example Output

```
Domain: mycompany.internal
  -> IP: 192.168.31.1 (Private/Bogon)
     - Info Error: Bogon or not publicly accessible

Domain: google.com
  -> IP: 142.250.183.174 (Public)
     - Org: AS15169 Google LLC
     - Location: Mountain View, California, US
```

---

## 📂 Folder Structure

```
.
├── ip_extractor.py       # Main script
├── README.md             # You're here
└── requirements.txt      # Python dependencies (just 'requests')
```

---

## 🔐 Notes

* Private/Bogon IPs are often seen in internal networks and aren't useful in public bug bounty recon.
* Public IPs are enriched using the free `ipinfo.io` API. For higher rate limits, consider using an API token.

---

## 🤖 Future Plans

* [ ] Bulk domain support
* [ ] Save results as JSON/CSV
* [ ] Add Nmap integration for public IPs
* [ ] Turn into a terminal-based tool with flags

---

## 🧑‍💻 Author

Made with ☕ and `socket` by [Utkarsh Raj](https://github.com/utkarsh-404)

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

```
