#!/usr/bin/env python3
"""
WatchTower - Network Auditing Tool
Author: 0xS4r4n9
Version: 1.0.0
"""

import os
import sys
import json
import time
import socket
import struct
import ipaddress
import threading
import subprocess
import argparse
import re
import csv
import datetime
import platform
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK & AUTO-INSTALL
# Handles Kali Linux / Debian "externally-managed-environment" (PEP 668)
# ─────────────────────────────────────────────────────────────────────────────

def check_and_install(package, import_name=None):
    import_name = import_name or package
    try:
        __import__(import_name)
        return  # already installed
    except ImportError:
        pass

    print(f"  [*] Installing {package}...")

    # Strategy 1: plain pip (works in venvs / older systems)
    r = subprocess.run(
        [sys.executable, "-m", "pip", "install", package, "-q"],
        capture_output=True
    )
    if r.returncode == 0:
        return

    # Strategy 2: --break-system-packages (Kali / Debian PEP 668)
    r = subprocess.run(
        [sys.executable, "-m", "pip", "install", package, "-q",
         "--break-system-packages"],
        capture_output=True
    )
    if r.returncode == 0:
        return

    # Strategy 3: pipx (application-level installs)
    r = subprocess.run(
        ["pipx", "install", package],
        capture_output=True
    )
    if r.returncode == 0:
        return

    # If all strategies fail, warn but don't crash — some features may be limited
    print(f"  [!] Could not auto-install '{package}'. "
          f"Try manually: pip install {package} --break-system-packages")


REQUIRED = [
    ("rich",         "rich"),
    ("requests",     "requests"),
    ("python-nmap",  "nmap"),
    ("reportlab",    "reportlab"),
    ("netifaces",    "netifaces"),
    ("scapy",        "scapy"),
    ("paramiko",     "paramiko"),
    ("python-whois", "whois"),
    ("dnspython",    "dns"),
    ("colorama",     "colorama"),
    # ftplib is stdlib — no install needed
]

print("[*] Checking dependencies...")
for pkg, imp in REQUIRED:
    check_and_install(pkg, imp)

# ─────────────────────────────────────────────────────────────────────────────
# IMPORTS (after install check)
# ─────────────────────────────────────────────────────────────────────────────

import nmap
import requests
import socket
import netifaces
import paramiko
import ftplib

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich.columns import Columns
from rich.tree import Tree
from rich.layout import Layout
from rich.rule import Rule
from rich import box
from rich.style import Style
from rich.markup import escape

try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except Exception:
    DNS_AVAILABLE = False

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table as RLTable,
                                 TableStyle, PageBreak, HRFlowable)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
 ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗████████╗ ██████╗ ██╗    ██╗███████╗██████╗ 
 ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║╚══██╔══╝██╔═══██╗██║    ██║██╔════╝██╔══██╗
 ██║ █╗ ██║███████║   ██║   ██║     ███████║   ██║   ██║   ██║██║ █╗ ██║█████╗  ██████╔╝
 ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║   ██║   ██║   ██║██║███╗██║██╔══╝  ██╔══██╗
 ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║   ██║   ╚██████╔╝╚███╔███╔╝███████╗██║  ██║
  ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝
"""

def print_banner():
    console.print(BANNER, style="bold cyan")
    console.print(Panel.fit(
        "[bold white]Network Auditing Tool[/bold white] [dim]by[/dim] [bold magenta]0xS4r4n9[/bold magenta]\n"
        "[dim]Version 1.0.0 | Professional Penetration Testing Suite[/dim]",
        border_style="cyan",
        padding=(0, 4),
    ))
    console.print()

# ─────────────────────────────────────────────────────────────────────────────
# COLOUR HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def severity_color(sev):
    return {"critical": "bold red", "high": "red", "medium": "yellow",
            "low": "cyan", "info": "green", "none": "white"}.get(sev.lower(), "white")

def cvss_severity(score):
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "none"

def print_section(title, emoji=""):
    console.print()
    console.print(Rule(f"[bold cyan]{emoji} {title}[/bold cyan]", style="cyan"))

def print_finding(level, msg):
    icons = {"critical": "💀", "high": "🔴", "medium": "🟡", "low": "🔵", "info": "🟢"}
    color = severity_color(level)
    icon = icons.get(level, "•")
    console.print(f"  {icon} [{color}]{msg}[/{color}]")

def status(msg):
    console.print(f"  [dim cyan]→[/dim cyan] [white]{msg}[/white]")

# ─────────────────────────────────────────────────────────────────────────────
# NETWORK DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

class NetworkDiscovery:
    def __init__(self, target):
        self.target = target
        self.hosts = []

    def get_local_network(self):
        """Auto-detect local subnet"""
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface.startswith('lo'): continue
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr.get('addr')
                        netmask = addr.get('netmask')
                        if ip and netmask and not ip.startswith('127.'):
                            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            return str(network), iface
        except Exception as e:
            pass
        return None, None

    def arp_sweep(self, network):
        """ARP scan to discover live hosts"""
        hosts = []
        if not SCAPY_AVAILABLE:
            status("Scapy not available, falling back to ping sweep")
            return self.ping_sweep(network)
        try:
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=3, verbose=0)[0]
            for sent, received in result:
                hosts.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "hostname": self._resolve(received.psrc),
                })
        except Exception as e:
            status(f"ARP sweep failed: {e}, falling back to ping")
            return self.ping_sweep(network)
        return hosts

    def ping_sweep(self, network):
        """ICMP ping sweep fallback"""
        hosts = []
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            targets = list(net.hosts())
            if len(targets) > 254:
                targets = targets[:254]

            def ping_host(ip):
                ip = str(ip)
                try:
                    result = subprocess.run(
                        ["ping", "-c", "1", "-W", "1", ip],
                        capture_output=True, timeout=3
                    )
                    if result.returncode == 0:
                        return {"ip": ip, "mac": "N/A", "hostname": self._resolve(ip)}
                except Exception:
                    pass
                return None

            with ThreadPoolExecutor(max_workers=50) as ex:
                futures = {ex.submit(ping_host, ip): ip for ip in targets}
                for f in as_completed(futures):
                    r = f.result()
                    if r:
                        hosts.append(r)
        except Exception as e:
            console.print(f"  [red]Ping sweep error: {e}[/red]")
        return hosts

    def _resolve(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip

    def run(self):
        print_section("Network Discovery", "🌐")
        if self.target == "auto":
            network, iface = self.get_local_network()
            if not network:
                console.print("[red]Could not detect local network[/red]")
                return []
            console.print(f"  [green]Interface:[/green] [bold]{iface}[/bold]  [green]Network:[/green] [bold]{network}[/bold]")
            with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), console=console) as prog:
                task = prog.add_task("ARP sweep...", total=None)
                self.hosts = self.arp_sweep(network)
        else:
            # Single target or CIDR
            if "/" in self.target:
                with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), console=console) as prog:
                    task = prog.add_task("Sweeping network...", total=None)
                    self.hosts = self.arp_sweep(self.target)
            else:
                self.hosts = [{"ip": self.target, "mac": "N/A", "hostname": self._resolve(self.target)}]

        # Display results
        if self.hosts:
            t = Table(title="[bold cyan]Discovered Hosts[/bold cyan]", box=box.ROUNDED, border_style="cyan")
            t.add_column("IP", style="bold yellow")
            t.add_column("Hostname", style="white")
            t.add_column("MAC", style="dim")
            for h in sorted(self.hosts, key=lambda x: x["ip"]):
                t.add_row(h["ip"], h["hostname"], h["mac"])
            console.print(t)
            console.print(f"\n  [bold green]✓ {len(self.hosts)} host(s) discovered[/bold green]")
        else:
            console.print("  [yellow]No hosts discovered[/yellow]")
        return self.hosts

# ─────────────────────────────────────────────────────────────────────────────
# PORT SCANNER
# ─────────────────────────────────────────────────────────────────────────────

SERVICE_VULN_MAP = {
    "ftp":       ["anonymous_ftp", "ftp_brute"],
    "ssh":       ["ssh_brute", "ssh_version"],
    "telnet":    ["telnet_brute", "telnet_banner"],
    "smtp":      ["smtp_enum", "smtp_relay"],
    "http":      ["http_methods", "http_headers", "dir_enum", "ssl_check"],
    "https":     ["ssl_check", "http_methods", "http_headers", "dir_enum"],
    "smb":       ["smb_enum", "smb_vulns", "smb_null_session"],
    "rdp":       ["rdp_check", "ssl_check"],
    "mysql":     ["mysql_brute", "mysql_info"],
    "mssql":     ["mssql_brute", "mssql_info"],
    "postgresql":["pg_brute"],
    "vnc":       ["vnc_brute", "vnc_info"],
    "snmp":      ["snmp_enum"],
    "ldap":      ["ldap_enum"],
    "nfs":       ["nfs_enum"],
    "pop3":      ["pop3_brute"],
    "imap":      ["imap_brute"],
    "redis":     ["redis_unauth"],
    "mongodb":   ["mongo_unauth"],
    "elasticsearch": ["es_unauth"],
    "memcached": ["memcached_unauth"],
}

class PortScanner:
    def __init__(self, host, port_range="1-65535", fast=False):
        self.host = host
        self.port_range = "1-1024" if fast else port_range
        self.nm = nmap.PortScanner()
        self.results = {}

    def scan(self):
        print_section(f"Port Scan: {self.host}", "🔍")
        args = f"-sV -sC --script=banner,vulners -O --open -T4"
        try:
            with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                          TimeElapsedColumn(), console=console) as prog:
                task = prog.add_task(f"Scanning {self.host} [{self.port_range}]...", total=None)
                self.nm.scan(hosts=self.host, ports=self.port_range, arguments=args)
        except Exception as e:
            console.print(f"  [red]Scan error: {e}[/red]")
            return {}

        if self.host not in self.nm.all_hosts():
            console.print(f"  [yellow]Host {self.host} did not respond[/yellow]")
            return {}

        host_data = self.nm[self.host]
        self.results = {
            "ip": self.host,
            "hostname": host_data.hostname(),
            "state": host_data.state(),
            "os": self._get_os(host_data),
            "ports": [],
        }

        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                p = host_data[proto][port]
                if p["state"] != "open":
                    continue
                port_info = {
                    "port": port,
                    "proto": proto,
                    "service": p.get("name", "unknown"),
                    "version": p.get("version", ""),
                    "product": p.get("product", ""),
                    "extrainfo": p.get("extrainfo", ""),
                    "cpe": p.get("cpe", ""),
                    "scripts": p.get("script", {}),
                    "state": p["state"],
                    "tests_to_run": [],
                }
                # Map service to tests
                svc = p.get("name", "").lower()
                for k, v in SERVICE_VULN_MAP.items():
                    if k in svc:
                        port_info["tests_to_run"] = v
                        break
                self.results["ports"].append(port_info)

        self._display_results()
        return self.results

    def _get_os(self, host_data):
        try:
            matches = host_data["osmatch"]
            if matches:
                return matches[0]["name"]
        except Exception:
            pass
        return "Unknown"

    def _display_results(self):
        t = Table(box=box.ROUNDED, border_style="cyan",
                  title=f"[bold cyan]Open Ports — {self.results['ip']}[/bold cyan]")
        t.add_column("Port", style="bold yellow", width=8)
        t.add_column("Proto", style="dim", width=6)
        t.add_column("Service", style="bold green", width=14)
        t.add_column("Version/Product", style="white")
        t.add_column("Tests Queued", style="magenta")

        for p in self.results["ports"]:
            ver = " ".join(filter(None, [p["product"], p["version"], p["extrainfo"]]))
            tests = ", ".join(p["tests_to_run"][:3]) + ("..." if len(p["tests_to_run"]) > 3 else "")
            t.add_row(str(p["port"]), p["proto"], p["service"], ver or "-", tests or "-")

        console.print(t)
        if self.results.get("os"):
            console.print(f"  [bold green]OS Detection:[/bold green] [yellow]{self.results['os']}[/yellow]")

# ─────────────────────────────────────────────────────────────────────────────
# SERVICE AUDITORS
# ─────────────────────────────────────────────────────────────────────────────

class ServiceAuditor:
    """Run targeted checks per service"""
    COMMON_USERS  = ["admin", "root", "administrator", "user", "test", "guest", "sa", "postgres", "oracle"]
    COMMON_PASSES = ["admin", "password", "123456", "root", "toor", "admin123", "", "pass",
                     "letmein", "welcome", "changeme", "12345678", "qwerty", "abc123"]

    def __init__(self, host, port_data, findings):
        self.host = host
        self.port_data = port_data
        self.findings = findings  # shared list

    def _add_finding(self, sev, title, detail, port=None, cve=None, cvss=None):
        self.findings.append({
            "severity": sev, "title": title, "detail": detail,
            "port": port, "cve": cve, "cvss": cvss,
            "host": self.host,
        })
        print_finding(sev, f"[{port or '?'}] {title}")

    # ── FTP ──────────────────────────────────────────────────────────────────
    def check_anonymous_ftp(self, port=21):
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.host, port, timeout=5)
            ftp.login("anonymous", "anonymous@test.com")
            files = ftp.nlst()
            ftp.quit()
            self._add_finding("high", "FTP Anonymous Login Enabled",
                f"Anonymous FTP access granted. Files: {files[:5]}", port=port,
                cve="CVE-1999-0497", cvss=7.5)
        except ftplib.error_perm:
            pass
        except Exception:
            pass

    def brute_ftp(self, port=21):
        for user in self.COMMON_USERS[:5]:
            for pw in self.COMMON_PASSES[:8]:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(self.host, port, timeout=3)
                    ftp.login(user, pw)
                    ftp.quit()
                    self._add_finding("critical", f"FTP Weak Credentials: {user}/{pw}",
                        f"FTP login succeeded with {user}:{pw}", port=port, cvss=9.8)
                    return
                except Exception:
                    pass

    # ── SSH ──────────────────────────────────────────────────────────────────
    def brute_ssh(self, port=22):
        for user in self.COMMON_USERS[:5]:
            for pw in self.COMMON_PASSES[:8]:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.host, port=port, username=user, password=pw,
                                timeout=4, banner_timeout=5)
                    ssh.close()
                    self._add_finding("critical", f"SSH Weak Credentials: {user}/{pw}",
                        f"SSH login succeeded with {user}:{pw}", port=port, cvss=9.8)
                    return
                except paramiko.AuthenticationException:
                    pass
                except Exception:
                    break

    def check_ssh_version(self, port=22):
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.host, port))
            banner = s.recv(256).decode(errors="ignore").strip()
            s.close()
            if "OpenSSH" in banner:
                ver_match = re.search(r"OpenSSH[_ ](\d+\.\d+)", banner)
                if ver_match:
                    ver = float(ver_match.group(1))
                    if ver < 7.4:
                        self._add_finding("medium", f"Outdated OpenSSH: {banner}",
                            "Old OpenSSH may be vulnerable to multiple CVEs", port=port,
                            cve="CVE-2016-10012", cvss=5.3)
        except Exception:
            pass

    # ── HTTP/HTTPS ────────────────────────────────────────────────────────────
    def check_http_headers(self, port=80):
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{self.host}:{port}"
        try:
            r = requests.get(url, timeout=6, verify=False, allow_redirects=True)
            headers = r.headers
            missing = []
            checks = {
                "X-Frame-Options": "Clickjacking protection missing",
                "X-Content-Type-Options": "MIME-sniffing protection missing",
                "Strict-Transport-Security": "HSTS not enforced",
                "Content-Security-Policy": "CSP header missing",
                "X-XSS-Protection": "XSS filter header missing",
            }
            for h, desc in checks.items():
                if h not in headers:
                    missing.append(f"{h}: {desc}")

            if missing:
                self._add_finding("low", "Missing Security Headers",
                    "\n".join(missing), port=port, cvss=4.3)

            server = headers.get("Server", "")
            if server:
                self._add_finding("info", f"Server Banner: {server}",
                    "Server header reveals software version", port=port, cvss=2.0)
        except Exception:
            pass

    def check_http_methods(self, port=80):
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{self.host}:{port}"
        try:
            r = requests.request("OPTIONS", url, timeout=5, verify=False)
            allow = r.headers.get("Allow", "")
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow]
            if dangerous:
                self._add_finding("medium", f"Dangerous HTTP Methods: {', '.join(dangerous)}",
                    f"OPTIONS response Allow: {allow}", port=port, cvss=5.3)
        except Exception:
            pass

    def check_ssl(self, port=443):
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    proto = ssock.version()

                    # Check expiry
                    if cert:
                        not_after = cert.get("notAfter")
                        if not_after:
                            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            if exp < datetime.datetime.utcnow():
                                self._add_finding("high", "SSL Certificate Expired",
                                    f"Certificate expired: {not_after}", port=port, cvss=7.4)
                            elif exp < datetime.datetime.utcnow() + datetime.timedelta(days=30):
                                self._add_finding("medium", "SSL Certificate Expiring Soon",
                                    f"Expires: {not_after}", port=port, cvss=5.0)

                    if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        self._add_finding("high", f"Weak TLS Version: {proto}",
                            "Outdated TLS/SSL protocol in use", port=port,
                            cve="CVE-2014-3566", cvss=7.4)

                    if cipher and cipher[0]:
                        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "anon"]
                        for w in weak_ciphers:
                            if w in cipher[0].upper():
                                self._add_finding("medium", f"Weak Cipher Suite: {cipher[0]}",
                                    "Weak cipher in use", port=port, cvss=5.9)
                                break
        except Exception:
            pass

    def dir_enum(self, port=80):
        """Quick directory enumeration"""
        scheme = "https" if port in (443, 8443) else "http"
        base = f"{scheme}://{self.host}:{port}"
        paths = [
            "/.git/config", "/.env", "/wp-admin", "/admin", "/phpmyadmin",
            "/manager/html", "/actuator", "/actuator/env", "/api/v1",
            "/.htaccess", "/server-status", "/crossdomain.xml", "/robots.txt",
            "/backup", "/config.php", "/web.config", "/info.php", "/phpinfo.php",
        ]
        for path in paths:
            try:
                r = requests.get(base + path, timeout=4, verify=False, allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    sev = "high" if r.status_code == 200 and path in ("/.git/config", "/.env", "/phpinfo.php") else "medium"
                    self._add_finding(sev, f"Sensitive Path Found: {path}",
                        f"Status {r.status_code} at {base}{path}", port=port, cvss=6.5)
            except Exception:
                pass

    # ── SMB ──────────────────────────────────────────────────────────────────
    def smb_enum(self, port=445):
        """Use nmap scripts for SMB"""
        try:
            nm = nmap.PortScanner()
            nm.scan(self.host, str(port),
                    arguments="--script smb-vuln-ms17-010,smb-security-mode,smb-enum-shares -T4")
            if self.host in nm.all_hosts():
                scripts = nm[self.host].get("tcp", {}).get(port, {}).get("script", {})
                if "smb-vuln-ms17-010" in scripts:
                    out = scripts["smb-vuln-ms17-010"]
                    if "VULNERABLE" in out:
                        self._add_finding("critical", "EternalBlue (MS17-010) VULNERABLE",
                            out[:300], port=port, cve="CVE-2017-0144", cvss=9.8)
                if "smb-security-mode" in scripts:
                    out = scripts["smb-security-mode"]
                    if "message_signing: disabled" in out.lower():
                        self._add_finding("medium", "SMB Signing Disabled",
                            "SMB signing not enforced — relay attacks possible", port=port,
                            cve="CVE-2017-0143", cvss=5.9)
                if "smb-enum-shares" in scripts:
                    self._add_finding("info", "SMB Shares Enumerated",
                        scripts["smb-enum-shares"][:400], port=port, cvss=3.1)
        except Exception:
            pass

    # ── SNMP ─────────────────────────────────────────────────────────────────
    def snmp_enum(self, port=161):
        try:
            nm = nmap.PortScanner()
            nm.scan(self.host, str(port),
                    arguments="-sU --script snmp-info,snmp-brute -T4")
            if self.host in nm.all_hosts():
                udp = nm[self.host].get("udp", {}).get(port, {})
                scripts = udp.get("script", {})
                if "snmp-brute" in scripts and "Valid credentials" in scripts["snmp-brute"]:
                    self._add_finding("high", "SNMP Default Community String",
                        scripts["snmp-brute"][:300], port=port, cvss=7.5)
        except Exception:
            pass

    # ── Redis ─────────────────────────────────────────────────────────────────
    def redis_unauth(self, port=6379):
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((self.host, port))
            s.sendall(b"PING\r\n")
            resp = s.recv(64).decode(errors="ignore")
            s.close()
            if "+PONG" in resp:
                self._add_finding("critical", "Redis Unauthenticated Access",
                    "Redis responds to PING without authentication", port=port,
                    cve="CVE-2022-0543", cvss=9.8)
        except Exception:
            pass

    # ── MySQL ─────────────────────────────────────────────────────────────────
    def mysql_brute(self, port=3306):
        try:
            nm = nmap.PortScanner()
            nm.scan(self.host, str(port), arguments="--script mysql-empty-password,mysql-brute -T4")
            if self.host in nm.all_hosts():
                scripts = nm[self.host].get("tcp", {}).get(port, {}).get("script", {})
                if "mysql-empty-password" in scripts:
                    out = scripts["mysql-empty-password"]
                    if "root account" in out.lower():
                        self._add_finding("critical", "MySQL Empty Root Password",
                            out[:300], port=port, cvss=9.8)
        except Exception:
            pass

    # ── VNC ──────────────────────────────────────────────────────────────────
    def vnc_info(self, port=5900):
        try:
            nm = nmap.PortScanner()
            nm.scan(self.host, str(port), arguments="--script vnc-info,vnc-brute -T4")
            if self.host in nm.all_hosts():
                scripts = nm[self.host].get("tcp", {}).get(port, {}).get("script", {})
                if "vnc-brute" in scripts and "Valid credentials" in scripts["vnc-brute"]:
                    self._add_finding("critical", "VNC Weak Credentials",
                        scripts["vnc-brute"][:300], port=port, cvss=9.8)
        except Exception:
            pass

    TEST_MAP = {
        "anonymous_ftp": (check_anonymous_ftp, "ftp"),
        "ftp_brute":     (brute_ftp,           "ftp"),
        "ssh_brute":     (brute_ssh,            "ssh"),
        "ssh_version":   (check_ssh_version,    "ssh"),
        "http_headers":  (check_http_headers,   "http"),
        "http_methods":  (check_http_methods,   "http"),
        "ssl_check":     (check_ssl,            "ssl"),
        "dir_enum":      (dir_enum,             "http"),
        "smb_enum":      (smb_enum,             "smb"),
        "smb_vulns":     (smb_enum,             "smb"),
        "smb_null_session": (smb_enum,          "smb"),
        "snmp_enum":     (snmp_enum,            "snmp"),
        "redis_unauth":  (redis_unauth,         "redis"),
        "mysql_brute":   (mysql_brute,          "mysql"),
        "vnc_brute":     (vnc_info,             "vnc"),
        "vnc_info":      (vnc_info,             "vnc"),
    }

    def run_tests(self, port_data):
        tests = port_data.get("tests_to_run", [])
        port = port_data["port"]
        run = set()
        for test in tests:
            if test in self.TEST_MAP and test not in run:
                func, _ = self.TEST_MAP[test]
                try:
                    func(self, port)
                except Exception:
                    pass
                run.add(test)

# ─────────────────────────────────────────────────────────────────────────────
# EXPLOIT SEARCH
# ─────────────────────────────────────────────────────────────────────────────

class ExploitSearch:
    def __init__(self):
        self.results = []

    def searchsploit(self, query):
        """Search exploit-db via searchsploit"""
        try:
            result = subprocess.run(
                ["searchsploit", "--json", query],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                exploits = data.get("RESULTS_EXPLOIT", [])
                return exploits[:5]
        except FileNotFoundError:
            status("searchsploit not found — install exploitdb")
        except Exception as e:
            pass
        return []

    def search_cve_nvd(self, product, version=""):
        """Query NVD API for CVEs"""
        cves = []
        try:
            keyword = f"{product} {version}".strip()
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5"
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")
                    desc = cve.get("descriptions", [{}])[0].get("value", "")[:150]
                    metrics = cve.get("metrics", {})
                    score = 0.0
                    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        m = metrics.get(k, [{}])
                        if m:
                            score = m[0].get("cvssData", {}).get("baseScore", 0.0)
                            break
                    if cve_id:
                        cves.append({"id": cve_id, "desc": desc, "score": score})
        except Exception:
            pass
        return cves

    def display_exploits(self, host, port, service, product, version):
        query = f"{product or service} {version}".strip()
        if not query or len(query) < 3:
            return []

        print_section(f"Exploit Search: {service} ({query})", "💣")

        exploits = self.searchsploit(query)
        cves = self.search_cve_nvd(product or service, version)

        found = []
        if exploits:
            t = Table(box=box.SIMPLE, title="[red]SearchSploit Results[/red]")
            t.add_column("EDB-ID", style="yellow", width=10)
            t.add_column("Title", style="white")
            t.add_column("Path", style="dim")
            for e in exploits[:5]:
                t.add_row(str(e.get("EDB-ID", "")), e.get("Title", "")[:60], e.get("Path", ""))
                found.append(e)
            console.print(t)

        if cves:
            t = Table(box=box.SIMPLE, title="[red]NVD CVEs[/red]")
            t.add_column("CVE-ID", style="yellow", width=20)
            t.add_column("CVSS", style="bold red", width=6)
            t.add_column("Severity", style="bold", width=10)
            t.add_column("Description", style="white")
            for c in cves:
                sev = cvss_severity(c["score"])
                color = severity_color(sev)
                t.add_row(c["id"], str(c["score"]),
                          f"[{color}]{sev.upper()}[/{color}]",
                          c["desc"][:80])
                found.append(c)
            console.print(t)

        return found

# ─────────────────────────────────────────────────────────────────────────────
# NETWORK TOPOLOGY
# ─────────────────────────────────────────────────────────────────────────────

def print_topology(hosts_data):
    """ASCII topology using Rich Tree"""
    print_section("Network Topology", "🗺️")
    tree = Tree("[bold cyan]🌐 Network[/bold cyan]")
    for hd in hosts_data:
        ip = hd.get("ip", "?")
        hostname = hd.get("hostname", ip)
        os_info = hd.get("os", "Unknown OS")
        host_node = tree.add(f"[bold yellow]🖥  {ip}[/bold yellow] [dim]({hostname})[/dim] [green]{os_info}[/green]")
        for p in hd.get("ports", []):
            port = p["port"]
            svc = p["service"]
            ver = p.get("version", "")
            ver_str = f" [dim]{ver}[/dim]" if ver else ""
            host_node.add(f"[cyan]{port}/tcp[/cyan] [bold]{svc}[/bold]{ver_str}")
    console.print(tree)

# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    def __init__(self, hosts_data, findings, output_path="watchtower_report.pdf"):
        self.hosts_data = hosts_data
        self.findings = findings
        self.output_path = output_path
        self.generated = datetime.datetime.now()

    def _severity_counts(self):
        counts = defaultdict(int)
        for f in self.findings:
            counts[f["severity"]] += 1
        return counts

    def _color_for_sev(self, sev):
        return {
            "critical": colors.HexColor("#c0392b"),
            "high":     colors.HexColor("#e74c3c"),
            "medium":   colors.HexColor("#e67e22"),
            "low":      colors.HexColor("#3498db"),
            "info":     colors.HexColor("#27ae60"),
        }.get(sev.lower(), colors.grey)

    def generate_pdf(self):
        doc = SimpleDocTemplate(self.output_path, pagesize=A4,
                                leftMargin=0.75*inch, rightMargin=0.75*inch,
                                topMargin=1*inch, bottomMargin=1*inch)
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle("WTTitle", parent=styles["Title"],
                                     fontSize=28, textColor=colors.HexColor("#1a1a2e"),
                                     spaceAfter=6, fontName="Helvetica-Bold")
        h1 = ParagraphStyle("WTH1", parent=styles["Heading1"],
                            fontSize=16, textColor=colors.HexColor("#16213e"),
                            spaceAfter=8, spaceBefore=16, fontName="Helvetica-Bold")
        h2 = ParagraphStyle("WTH2", parent=styles["Heading2"],
                            fontSize=12, textColor=colors.HexColor("#0f3460"),
                            spaceAfter=6, spaceBefore=10, fontName="Helvetica-Bold")
        body = ParagraphStyle("WTBody", parent=styles["Normal"],
                              fontSize=9, leading=13, spaceAfter=4)
        code_style = ParagraphStyle("WTCode", parent=styles["Code"],
                                    fontSize=8, fontName="Courier",
                                    backColor=colors.HexColor("#f8f9fa"),
                                    borderPad=4, leading=11)

        story = []

        # ── Cover Page ──────────────────────────────────────────────────────
        story.append(Spacer(1, 1.5*inch))
        story.append(Paragraph("WatchTower", title_style))
        story.append(Paragraph("Network Security Audit Report", styles["Heading2"]))
        story.append(Spacer(1, 0.3*inch))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#e74c3c")))
        story.append(Spacer(1, 0.2*inch))

        meta = [
            ["Report Date", self.generated.strftime("%Y-%m-%d %H:%M:%S")],
            ["Generated By", "WatchTower v1.0 by 0xS4r4n9"],
            ["Hosts Scanned", str(len(self.hosts_data))],
            ["Total Findings", str(len(self.findings))],
        ]
        sev_counts = self._severity_counts()
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev_counts[sev]:
                meta.append([sev.capitalize(), str(sev_counts[sev])])

        mt = RLTable(meta, colWidths=[2*inch, 4*inch])
        mt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",  (0, 0), (0, -1), colors.white),
            ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.whitesmoke, colors.white]),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(mt)
        story.append(PageBreak())

        # ── Executive Summary ───────────────────────────────────────────────
        story.append(Paragraph("1. Executive Summary", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f3460")))
        story.append(Spacer(1, 0.1*inch))
        story.append(Paragraph(
            f"WatchTower performed an automated security audit of {len(self.hosts_data)} host(s). "
            f"A total of {len(self.findings)} security findings were identified. "
            f"Critical issues require immediate attention. "
            f"This report provides detailed technical findings, risk scoring, and remediation guidance.",
            body))

        # Severity summary table
        sev_table_data = [["Severity", "Count", "Risk Level"]]
        for sev in ("critical", "high", "medium", "low", "info"):
            count = sev_counts.get(sev, 0)
            if count:
                sev_table_data.append([sev.capitalize(), str(count),
                    {"critical": "Immediate Action", "high": "Urgent",
                     "medium": "Moderate", "low": "Low Priority", "info": "Informational"}[sev]])
        st = RLTable(sev_table_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
        st.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        for i, row in enumerate(sev_table_data[1:], 1):
            sev = row[0].lower()
            st.setStyle(TableStyle([
                ("TEXTCOLOR", (0, i), (0, i), self._color_for_sev(sev)),
                ("FONTNAME",  (0, i), (0, i), "Helvetica-Bold"),
            ]))
        story.append(Spacer(1, 0.1*inch))
        story.append(st)
        story.append(PageBreak())

        # ── Hosts Overview ──────────────────────────────────────────────────
        story.append(Paragraph("2. Scanned Hosts", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f3460")))
        for hd in self.hosts_data:
            story.append(Paragraph(f"{hd.get('ip')} — {hd.get('hostname', 'N/A')}", h2))
            story.append(Paragraph(f"<b>OS:</b> {hd.get('os', 'Unknown')} &nbsp; <b>State:</b> {hd.get('state','')}", body))
            ports = hd.get("ports", [])
            if ports:
                pt_data = [["Port", "Protocol", "Service", "Version"]]
                for p in ports:
                    ver = " ".join(filter(None, [p.get("product",""), p.get("version","")]))
                    pt_data.append([str(p["port"]), p["proto"], p["service"], ver or "-"])
                pt = RLTable(pt_data, colWidths=[0.8*inch, 0.8*inch, 1.5*inch, 4*inch])
                pt.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
                    ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                    ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE",   (0, 0), (-1, -1), 8),
                    ("GRID",       (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
                    ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]))
                story.append(pt)
            story.append(Spacer(1, 0.15*inch))

        story.append(PageBreak())

        # ── Findings ────────────────────────────────────────────────────────
        story.append(Paragraph("3. Security Findings", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f3460")))
        story.append(Spacer(1, 0.1*inch))

        sorted_findings = sorted(self.findings, key=lambda f:
            {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(f["severity"].lower(), 5))

        for i, finding in enumerate(sorted_findings, 1):
            sev = finding["severity"].lower()
            clr = self._color_for_sev(sev)
            sev_style = ParagraphStyle(f"sev_{i}", parent=body,
                                       textColor=clr, fontName="Helvetica-Bold")
            story.append(Paragraph(
                f"[{i}] {finding['title']}",
                ParagraphStyle(f"ftitle_{i}", parent=h2, textColor=colors.HexColor("#1a1a2e"))))
            story.append(Paragraph(
                f"<b>Severity:</b> {sev.capitalize()} &nbsp; "
                f"<b>Host:</b> {finding.get('host','N/A')} &nbsp; "
                f"<b>Port:</b> {finding.get('port','N/A')} &nbsp; "
                + (f"<b>CVE:</b> {finding['cve']}" if finding.get('cve') else "") +
                (f" &nbsp; <b>CVSS:</b> {finding.get('cvss','')}" if finding.get('cvss') else ""),
                body))
            if finding.get("detail"):
                story.append(Paragraph(
                    finding["detail"].replace("\n", "<br/>")[:600],
                    code_style))
            story.append(Spacer(1, 0.1*inch))

        # ── Recommendations ─────────────────────────────────────────────────
        story.append(PageBreak())
        story.append(Paragraph("4. Recommendations", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f3460")))
        recs = {
            "critical": "Address all critical vulnerabilities immediately. Patch, disable, or isolate affected services.",
            "high":     "Schedule urgent remediation within 7 days. Apply vendor patches and review access controls.",
            "medium":   "Remediate within 30 days. Harden configurations and apply security best practices.",
            "low":      "Address during normal maintenance cycles. Review and tighten security policies.",
            "info":     "Review informational findings for hardening opportunities.",
        }
        for sev, rec in recs.items():
            if sev_counts.get(sev, 0) > 0:
                story.append(Paragraph(f"{sev.capitalize()} Priority", h2))
                story.append(Paragraph(rec, body))

        # ── Footer ───────────────────────────────────────────────────────────
        story.append(Spacer(1, 0.3*inch))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
        story.append(Paragraph(
            f"<i>Report generated by WatchTower v1.0 by 0xS4r4n9 on "
            f"{self.generated.strftime('%Y-%m-%d %H:%M:%S')} — CONFIDENTIAL</i>",
            ParagraphStyle("footer", parent=body, fontSize=7, textColor=colors.grey,
                           alignment=TA_CENTER)))

        doc.build(story)
        return self.output_path

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class WatchTower:
    def __init__(self, args):
        self.args = args
        self.all_hosts_data = []
        self.all_findings = []
        self.exploit_results = []

    def run(self):
        print_banner()

        # ── Discovery ─────────────────────────────────────────────────────
        disco = NetworkDiscovery(self.args.target)
        live_hosts = disco.run()

        if not live_hosts:
            console.print("[red]No hosts to scan. Exiting.[/red]")
            sys.exit(1)

        # ── Scan each host ────────────────────────────────────────────────
        exploit_searcher = ExploitSearch()

        for h in live_hosts:
            ip = h["ip"]
            console.print(f"\n[bold magenta]{'═'*60}[/bold magenta]")
            console.print(f"[bold magenta]  TARGET: {ip}[/bold magenta]")
            console.print(f"[bold magenta]{'═'*60}[/bold magenta]")

            # Port scan
            scanner = PortScanner(ip, self.args.ports, fast=self.args.fast)
            host_data = scanner.scan()
            if not host_data:
                continue
            host_data.update({"mac": h.get("mac","N/A")})
            self.all_hosts_data.append(host_data)

            # Service audits
            if not self.args.no_audit:
                print_section(f"Service Audit: {ip}", "🧪")
                auditor = ServiceAuditor(ip, host_data["ports"], self.all_findings)
                with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                              console=console) as prog:
                    for p in host_data["ports"]:
                        prog.add_task(f"Testing {p['service']}:{p['port']}...", total=None)
                        auditor.run_tests(p)

            # Exploit search
            if not self.args.no_exploits:
                for p in host_data["ports"]:
                    product = p.get("product", "")
                    version = p.get("version", "")
                    if product or p["service"] not in ("tcpwrapped", "unknown"):
                        r = exploit_searcher.display_exploits(
                            ip, p["port"], p["service"], product, version)
                        self.exploit_results.extend(r)

        # ── Topology ──────────────────────────────────────────────────────
        print_topology(self.all_hosts_data)

        # ── Findings Summary ─────────────────────────────────────────────
        self._print_findings_summary()

        # ── Report ───────────────────────────────────────────────────────
        if not self.args.no_report:
            report_path = self.args.output or f"watchtower_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            print_section("Generating Report", "📋")
            with Progress(SpinnerColumn(), TextColumn("[cyan]Building PDF report..."),
                          console=console) as prog:
                prog.add_task("", total=None)
                gen = ReportGenerator(self.all_hosts_data, self.all_findings, report_path)
                gen.generate_pdf()
            console.print(f"\n  [bold green]✓ Report saved:[/bold green] [bold yellow]{report_path}[/bold yellow]")

        console.print()
        console.print(Panel.fit(
            f"[bold green]WatchTower scan complete![/bold green]\n"
            f"[white]Hosts: [bold]{len(self.all_hosts_data)}[/bold] | "
            f"Findings: [bold]{len(self.all_findings)}[/bold][/white]",
            border_style="green"))

    def _print_findings_summary(self):
        print_section("Findings Summary", "📊")
        if not self.all_findings:
            console.print("  [green]No significant findings[/green]")
            return

        counts = defaultdict(int)
        for f in self.all_findings:
            counts[f["severity"]] += 1

        t = Table(box=box.ROUNDED, border_style="cyan", title="[bold]Security Findings[/bold]")
        t.add_column("Severity", width=12)
        t.add_column("Count", justify="right", width=8)
        t.add_column("Risk", width=20)

        risk_map = {"critical": "Immediate Action", "high": "Urgent",
                    "medium": "Moderate", "low": "Low Priority", "info": "Informational"}
        for sev in ("critical", "high", "medium", "low", "info"):
            c = counts.get(sev, 0)
            if c:
                color = severity_color(sev)
                t.add_row(f"[{color}]{sev.upper()}[/{color}]",
                          f"[bold]{c}[/bold]", risk_map[sev])
        console.print(t)

        # Detail table
        t2 = Table(box=box.SIMPLE, title="[bold]Finding Details[/bold]", show_lines=True)
        t2.add_column("Sev", width=10)
        t2.add_column("Host", width=16)
        t2.add_column("Port", width=6)
        t2.add_column("Title", width=40)
        t2.add_column("CVE", width=18)
        t2.add_column("CVSS", width=6)
        for f in sorted(self.all_findings,
                         key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x["severity"].lower(),5)):
            sev = f["severity"].lower()
            color = severity_color(sev)
            cvss = str(f.get("cvss","")) if f.get("cvss") else ""
            t2.add_row(
                f"[{color}]{sev.upper()}[/{color}]",
                f["host"], str(f.get("port","")),
                escape(f["title"][:40]),
                f.get("cve","") or "", cvss
            )
        console.print(t2)

# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="WatchTower — Network Auditing Tool by 0xS4r4n9",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 watchtower.py -t auto
  sudo python3 watchtower.py -t 192.168.1.0/24
  sudo python3 watchtower.py -t 192.168.1.100
  sudo python3 watchtower.py -t 10.0.0.1 --fast --no-exploits
  sudo python3 watchtower.py -t 192.168.1.100 -o client_report.pdf
        """
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP, CIDR, or 'auto' for local network")
    parser.add_argument("-p", "--ports", default="1-65535",
                        help="Port range (default: 1-65535)")
    parser.add_argument("--fast", action="store_true",
                        help="Fast scan — top 1024 ports only")
    parser.add_argument("--no-audit", action="store_true",
                        help="Skip service audits / brute force")
    parser.add_argument("--no-exploits", action="store_true",
                        help="Skip exploit search")
    parser.add_argument("--no-report", action="store_true",
                        help="Skip PDF report generation")
    parser.add_argument("-o", "--output",
                        help="Output PDF path (default: auto-named)")
    parser.add_argument("--version", action="version", version="WatchTower v1.0 by 0xS4r4n9")

    args = parser.parse_args()

    # Root check (needed for ARP / raw sockets)
    if os.geteuid() != 0:
        console.print("[yellow]⚠  Some features require root (ARP scan, OS detect). Run with sudo.[/yellow]")

    try:
        wt = WatchTower(args)
        wt.run()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user[/red]")
        sys.exit(0)

if __name__ == "__main__":
    main()
