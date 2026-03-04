<div align="center">

![WatchTower Banner](https://github.com/0xS4r4n9/watchtower/blob/main/watchtower_banner.svg)

# ReconTower 🗼

**Network Auditing & Penetration Testing Suite**

*by [0xS4r4n9](https://github.com/0xS4r4n9)*

---

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

</div>

---

## 📖 Overview

**ReconTower** is a comprehensive, automated network auditing and penetration testing tool built for security professionals and red teamers. It combines host discovery, port scanning, service enumeration, vulnerability detection, exploit intelligence, and professional PDF reporting — all in a single colorful, intuitive CLI tool.

> ⚠️ **Legal Disclaimer:** WatchTower is intended for use on networks and systems you own or have explicit written permission to test. Unauthorized use against systems you do not own is illegal. The author assumes no liability for misuse.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🌐 **Network Discovery** | ARP sweep + ping fallback to discover live hosts |
| 🔍 **Port Scanning** | Full nmap integration with service/version/OS detection |
| 🧪 **Service Auditing** | Automated per-service security checks |
| 🔑 **Credential Testing** | Brute force against FTP, SSH, MySQL, VNC, and more |
| 💣 **Exploit Search** | SearchSploit + NVD CVE API integration |
| 🔐 **SSL/TLS Analysis** | Certificate validation, weak protocols, weak ciphers |
| 🕷️ **Web Auditing** | Security headers, dangerous HTTP methods, sensitive path enumeration |
| 🗺️ **Network Topology** | Visual ASCII tree of hosts, ports, and services |
| 📊 **Findings Dashboard** | Color-coded severity table with CVE/CVSS scoring |
| 📋 **PDF Reporting** | Professional client-ready PDF reports |

---

## 🖥️ Screenshots

```
╔══════════════════════════════════════════════════════════════╗
║  🌐 Network Discovery                                        ║
║  ┌─────────────────────────────────────────────────────┐     ║
║  │ IP             Hostname           MAC               │     ║
║  │ 192.168.1.1    router.local       aa:bb:cc:dd:ee:ff │     ║
║  │ 192.168.1.100  webserver.local    11:22:33:44:55:66 │     ║
║  └─────────────────────────────────────────────────────┘     ║
║  ✓ 2 host(s) discovered                                      ║
╠══════════════════════════════════════════════════════════════╣
║  🔍 Port Scan: 192.168.1.100                                 ║
║  ┌──────┬────────┬──────────┬───────────────────────────┐    ║
║  │ Port │ Proto  │ Service  │ Version                   │    ║
║  │ 22   │ tcp    │ ssh      │ OpenSSH 7.4               │    ║
║  │ 80   │ tcp    │ http     │ Apache httpd 2.4.29       │    ║
║  │ 443  │ tcp    │ https    │ Apache httpd 2.4.29       │    ║
║  │ 3306 │ tcp    │ mysql    │ MySQL 5.7.38              │    ║
║  └──────┴────────┴──────────┴───────────────────────────┘    ║
╠══════════════════════════════════════════════════════════════╣
║  💀 [3306] MySQL Empty Root Password                         ║
║  🔴 [22]   Outdated OpenSSH: OpenSSH 7.4                    ║
║  🟡 [80]   Missing Security Headers                         ║
║  🟡 [80]   Dangerous HTTP Methods: TRACE, PUT               ║
║  🔵 [443]  SSL Certificate Expiring Soon                    ║
╚══════════════════════════════════════════════════════════════╝
```

---

## ⚙️ Installation

### Prerequisites

- **Kali Linux** (recommended) or any Debian-based Linux
- **Python 3.8+**
- **Nmap** installed
- **Root / sudo** privileges (required for ARP scanning and OS detection)

### 1. Clone the Repository

```bash
git clone https://github.com/0xS4r4n9/watchtower.git
cd watchtower
```

### 2. Install System Dependencies

```bash
# Nmap (usually pre-installed on Kali)
sudo apt-get install nmap -y

# ExploitDB / SearchSploit (usually pre-installed on Kali)
sudo apt-get install exploitdb -y
```

### 3. Install Python Dependencies

**Kali Linux / Modern Debian** (PEP 668 — externally managed environment):

```bash
pip install -r requirements.txt --break-system-packages
```

**Using a virtual environment** (cleanest approach, fully isolated):

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# Always run inside the venv:
sudo venv/bin/python3 watchtower.py -t auto
```

**Standard Linux / older systems:**

```bash
pip install -r requirements.txt
```

> 💡 WatchTower also attempts auto-install on first run using `--break-system-packages` as a fallback, so in most cases you can just run it directly.

### 4. Make Executable (optional)

```bash
chmod +x watchtower.py
```

---

## 🚀 Usage

```
sudo python3 watchtower.py -t <TARGET> [OPTIONS]
```

### Arguments

| Argument | Description |
|---|---|
| `-t`, `--target` | Target IP, CIDR range, or `auto` for local network |
| `-p`, `--ports` | Port range to scan (default: `1-65535`) |
| `--fast` | Fast mode — scan top 1024 ports only |
| `--no-audit` | Skip service audits and brute force checks |
| `--no-exploits` | Skip SearchSploit and CVE lookups |
| `--no-report` | Skip PDF report generation |
| `-o`, `--output` | Custom output path for the PDF report |
| `--version` | Show version and exit |

### Examples

```bash
# Auto-discover and scan entire local network
sudo python3 watchtower.py -t auto

# Scan a single host (full audit)
sudo python3 watchtower.py -t 192.168.1.100

# Scan a subnet
sudo python3 watchtower.py -t 192.168.1.0/24

# Fast scan with custom port range
sudo python3 watchtower.py -t 10.0.0.1 -p 1-1024 --fast

# Scan without brute force (quieter)
sudo python3 watchtower.py -t 192.168.1.100 --no-audit

# Scan and save report with custom filename
sudo python3 watchtower.py -t 192.168.1.0/24 -o client_pentest_report.pdf

# Skip exploit search for faster results
sudo python3 watchtower.py -t 192.168.1.100 --no-exploits
```

---

## 🔬 What Gets Tested

### Service Checks

| Service | Tests Performed |
|---|---|
| **FTP** (21) | Anonymous login, credential brute force |
| **SSH** (22) | Banner/version fingerprint, weak credential brute force |
| **HTTP** (80, 8080) | Security headers, dangerous methods, sensitive paths |
| **HTTPS** (443, 8443) | All HTTP checks + SSL/TLS certificate & cipher analysis |
| **SMB** (445) | EternalBlue (MS17-010), null sessions, share enumeration, signing |
| **MySQL** (3306) | Empty root password, credential brute force |
| **Redis** (6379) | Unauthenticated access (no-auth check) |
| **SNMP** (161) | Default community string enumeration |
| **VNC** (5900) | Credential brute force, version info |
| **SMTP** (25) | Open relay, user enumeration |
| **LDAP** (389) | Null bind, enumeration |
| **NFS** (2049) | Export enumeration |

### SSL/TLS Checks

- Certificate expiry and validity
- Deprecated protocol detection (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- Weak cipher suite detection (RC4, DES, 3DES, NULL, EXPORT)

### Web Checks

- Missing HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- Dangerous HTTP methods (PUT, DELETE, TRACE)
- Sensitive path discovery (`.env`, `.git/config`, `phpinfo.php`, `/admin`, etc.)
- Server version banner leakage

---

## 💣 Exploit Intelligence

WatchTower automatically queries two sources for each discovered service:

1. **SearchSploit (ExploitDB)** — searches the local exploit database for matching exploits
2. **NIST NVD API** — fetches real CVEs with CVSS scores for the detected product/version

Results include:
- CVE identifiers
- CVSS base scores
- Severity ratings (Critical / High / Medium / Low)
- Exploit paths (for SearchSploit results)

---

## 📋 Report

WatchTower generates a professional **PDF report** suitable for client delivery, containing:

- **Cover Page** — scan metadata, date, host count, finding totals
- **Executive Summary** — risk overview with severity breakdown table
- **Scanned Hosts** — open ports, services, and OS per host
- **Security Findings** — full detail for every finding with CVE, CVSS, and description
- **Recommendations** — prioritized remediation guidance by severity

---

## 🗺️ Network Topology

After scanning, WatchTower renders a visual tree of the network:

```
🌐 Network
├── 🖥  192.168.1.1  (router.local)  Linux 4.x
│   ├── 22/tcp  ssh      OpenSSH 8.2
│   └── 80/tcp  http     lighttpd 1.4
└── 🖥  192.168.1.100  (webserver.local)  Ubuntu 20.04
    ├── 22/tcp  ssh      OpenSSH 7.4
    ├── 80/tcp  http     Apache 2.4.29
    ├── 443/tcp https    Apache 2.4.29
    └── 3306/tcp mysql   MySQL 5.7.38
```

---

## 📦 Requirements

```
rich>=13.0.0
requests>=2.28.0
python-nmap>=0.7.1
reportlab>=4.0.0
netifaces>=0.11.0
scapy>=2.5.0
paramiko>=3.0.0
python-whois>=0.8.0
dnspython>=2.3.0
colorama>=0.4.6
```

> A `requirements.txt` is included in the repository.

---

## 🛡️ Severity Legend

| Icon | Level | CVSS Range | Action |
|---|---|---|---|
| 💀 | **CRITICAL** | 9.0 – 10.0 | Immediate action required |
| 🔴 | **HIGH** | 7.0 – 8.9 | Remediate within 7 days |
| 🟡 | **MEDIUM** | 4.0 – 6.9 | Remediate within 30 days |
| 🔵 | **LOW** | 0.1 – 3.9 | Address in maintenance cycle |
| 🟢 | **INFO** | N/A | Review for hardening |

---

## 🗂️ Project Structure

```
watchtower/
├── watchtower.py        # Main tool
├── requirements.txt     # Python dependencies
├── README.md            # This file
└── LICENSE              # MIT License
```

---

## ⚠️ Legal & Ethics

This tool is provided for **educational and authorized security testing purposes only**.

- Only use WatchTower on systems you **own** or have **explicit written authorization** to test.
- Running this tool against systems without permission is **illegal** and may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in your jurisdiction.
- The author, **0xS4r4n9**, accepts **no responsibility** for any illegal or unethical use of this tool.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Commit your changes (`git commit -m 'Add: new service checker'`)
4. Push to the branch (`git push origin feature/new-module`)
5. Open a Pull Request

Ideas for future modules: `Bluetooth scanning`, `IPv6 support`, `Metasploit RPC integration`, `Active Directory enumeration`, `Docker/Kubernetes checks`.

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Made with ❤️ and ☕ by [0xS4r4n9](https://github.com/0xS4r4n9)

*"Security is not a product, but a process."*

⭐ Star this repo if you find it useful!

</div>
