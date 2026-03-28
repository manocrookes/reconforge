# ReconForge

ReconForge is a reconnaissance toolkit designed to automate the **enumeration phase of penetration testing**.

It performs DNS resolution, subdomain discovery, HTTP enumeration, security header analysis, and port scanning using Nmap — generating structured JSON and human-readable Markdown reports.

---

## Features

* DNS Enumeration

  * A records
  * AAAA records
  * Reverse DNS
* Subdomain Enumeration

  * Custom wordlist support
  * Automatic detection of Kali (SecLists) wordlists
* HTTP Enumeration

  * Status code detection
  * Page title extraction
  * Header collection
* Security Headers Analysis

  * Detects missing common security headers
* Port Scanning

  * Nmap integration
  * Service detection
* Output Formats

  * JSON (machine-readable)
  * Markdown (human-readable reports)
* CLI Interface
* Custom output directory support

---

## Installation

### Requirements

* Python 3.10+
* Nmap installed

### Install Nmap (Kali Linux)

```bash
apt install nmap -y
```

### Setup Project

```bash
git clone https://github.com/manocrookes/reconforge.git
cd reconforge

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

---

## Usage

### Basic scan

```bash
python main.py run example.com
```

### Custom output directory

```bash
python main.py run example.com --output-dir results
```

### Custom wordlist

```bash
python main.py run example.com --wordlist wordlists/common.txt
```

---

## Example Scan

```bash
python main.py run scanme.nmap.org
```

### Output

```text
[+] ReconForge started
[+] Target: scanme.nmap.org
[+] Running DNS enumeration...
[+] Running subdomain enumeration...
[+] Wordlist in use: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] Running HTTP enumeration...
[+] Running port scan...
[+] Open ports found:
    - 22/tcp (ssh)
    - 80/tcp (http)
    - 9929/tcp (nping-echo)
    - 31337/tcp (Elite)
```

---

## Sample JSON Output

```json
{
  "target": "scanme.nmap.org",
  "target_type": "domain",
  "dns": {
    "a_records": ["45.33.32.156"],
    "aaaa_records": [],
    "reverse_dns": []
  },
  "subdomains": [],
  "http": {
    "status_code": 200,
    "title": "Go ahead and ScanMe!"
  },
  "ports": [
    {"port": 22, "service": "ssh"},
    {"port": 80, "service": "http"}
  ]
}
```

---

## Project Structure

```text
reconforge/
├── reconforge/
│   ├── core/
│   ├── modules/
│   ├── models/
│   ├── reports/
│   └── utils/
├── wordlists/
├── tests/
├── main.py
├── requirements.txt
└── README.md
```

---

## Security Disclaimer

This tool is intended for **authorized security testing and educational purposes only**.

Do not use ReconForge against systems without explicit permission.

---

## Roadmap

* [ ] Subdomain enumeration with threading
* [ ] Passive subdomain discovery (OSINT)
* [ ] Service fingerprinting
* [ ] HTML/CSV report output
* [ ] Async scanning engine
* [ ] Plugin system

---

## License

MIT License
