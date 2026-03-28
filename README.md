# ReconForge

ReconForge is a modular reconnaissance and enumeration toolkit designed for authorized penetration testing and red team operations.

It performs DNS resolution, reverse DNS lookup, HTTP enumeration, security header analysis, and basic port scanning using Nmap, generating structured JSON and human-readable Markdown reports.

---

## Features

- DNS Enumeration
  - A records
  - AAAA records
- Reverse DNS lookup for IP addresses
- HTTP Enumeration
  - Status code detection
  - Page title extraction
  - Header collection
- Security Headers Analysis
  - Detects common missing security headers
- Port Scanning
  - Nmap integration
  - Open ports and service detection
- Output Formats
  - JSON (machine-readable)
  - Markdown (human-readable reports)
- CLI Interface with argument validation
- Custom output directory support

---

## Installation

### Requirements

- Python 3.10+
- Nmap installed on system

### Install Nmap (Kali Linux)

```bash
apt install nmap -y
