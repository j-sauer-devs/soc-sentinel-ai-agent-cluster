"""Mock data layer for SOC Sentinel dashboard.

Generates realistic security alerts and simulated API responses
without requiring live API keys.
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

from server.models import Alert, AlertStatus, Severity

# ---------------------------------------------------------------------------
# Alert templates
# ---------------------------------------------------------------------------

_ALERT_TEMPLATES = [
    {
        "alert_type": "Brute Force Attempt",
        "description": "Multiple failed SSH login attempts detected from {src_ip} targeting {dst_ip}. {count} attempts in {minutes} minutes.",
        "severities": [Severity.HIGH, Severity.CRITICAL],
    },
    {
        "alert_type": "Suspicious Outbound Connection",
        "description": "Outbound connection from {src_ip} to known C2 infrastructure at {dst_ip}. Beaconing interval: {interval}s.",
        "severities": [Severity.CRITICAL],
    },
    {
        "alert_type": "DNS Query Anomaly",
        "description": "Unusual DNS query pattern from {src_ip}. High-entropy subdomain queries to {domain} — possible DNS tunneling.",
        "severities": [Severity.MEDIUM, Severity.HIGH],
    },
    {
        "alert_type": "Malware Download Attempt",
        "description": "Host {src_ip} attempted to download suspicious binary from {dst_ip}. SHA256: {sha256}.",
        "severities": [Severity.CRITICAL, Severity.HIGH],
    },
    {
        "alert_type": "Lateral Movement Detected",
        "description": "SMB/WinRM activity from {src_ip} to {dst_ip} using stolen credentials. MITRE T1021.",
        "severities": [Severity.HIGH, Severity.CRITICAL],
    },
    {
        "alert_type": "Data Exfiltration Attempt",
        "description": "Large outbound data transfer ({size} MB) from {src_ip} to external IP {dst_ip} over non-standard port {port}.",
        "severities": [Severity.CRITICAL],
    },
    {
        "alert_type": "Ransomware Indicator",
        "description": "File encryption activity detected on {src_ip}. {file_count} files renamed with .encrypted extension in {minutes} minutes.",
        "severities": [Severity.CRITICAL],
    },
    {
        "alert_type": "Suspicious Login",
        "description": "Login to {dst_ip} from unusual geolocation ({country}). Source: {src_ip}. Time: outside normal hours.",
        "severities": [Severity.MEDIUM, Severity.HIGH],
    },
    {
        "alert_type": "Port Scan Detected",
        "description": "Horizontal port scan from {src_ip} targeting subnet {subnet}. {port_count} ports probed across {host_count} hosts.",
        "severities": [Severity.MEDIUM, Severity.LOW],
    },
    {
        "alert_type": "Privilege Escalation",
        "description": "User on {src_ip} escalated to root/admin via {method}. Anomalous process tree detected.",
        "severities": [Severity.HIGH, Severity.CRITICAL],
    },
    {
        "alert_type": "Phishing Email Detected",
        "description": "Inbound email to {dst_ip} with malicious attachment from {src_ip}. Subject: '{subject}'.",
        "severities": [Severity.MEDIUM, Severity.HIGH],
    },
    {
        "alert_type": "Unauthorized Access Attempt",
        "description": "Access to restricted resource on {dst_ip} denied for {src_ip}. Repeated attempts ({count}) suggest targeted attack.",
        "severities": [Severity.MEDIUM, Severity.HIGH],
    },
    {
        "alert_type": "C2 Beacon Activity",
        "description": "Periodic HTTPS callbacks from {src_ip} to {dst_ip} every {interval}s. Traffic pattern matches Cobalt Strike profile.",
        "severities": [Severity.CRITICAL],
    },
    {
        "alert_type": "Credential Dumping",
        "description": "Process on {src_ip} accessed LSASS memory. Possible Mimikatz or comsvcs.dll credential extraction.",
        "severities": [Severity.CRITICAL],
    },
    {
        "alert_type": "Web Shell Detected",
        "description": "Suspicious web shell uploaded to {dst_ip}. File: /var/www/html/{filename}. Source: {src_ip}.",
        "severities": [Severity.CRITICAL, Severity.HIGH],
    },
    {
        "alert_type": "ARP Spoofing",
        "description": "ARP cache poisoning detected on segment {subnet}. Attacker: {src_ip}, impersonating gateway.",
        "severities": [Severity.HIGH],
    },
    {
        "alert_type": "SSL/TLS Certificate Anomaly",
        "description": "Self-signed certificate presented by {dst_ip} on port 443. Previously used valid certificate. Possible MitM.",
        "severities": [Severity.MEDIUM],
    },
    {
        "alert_type": "DDoS Traffic Spike",
        "description": "Inbound traffic spike to {dst_ip} from {src_count} unique sources. Peak rate: {rate} Mbps. Possible DDoS.",
        "severities": [Severity.HIGH, Severity.CRITICAL],
    },
    {
        "alert_type": "Cryptominer Detected",
        "description": "CPU spike on {src_ip} with connections to mining pool {dst_ip}:{port}. Process: {process}.",
        "severities": [Severity.MEDIUM],
    },
    {
        "alert_type": "Policy Violation",
        "description": "User on {src_ip} accessed {category} content via {dst_ip}. Violation of acceptable use policy.",
        "severities": [Severity.LOW, Severity.NOISE],
    },
]

# ---------------------------------------------------------------------------
# Helper data pools
# ---------------------------------------------------------------------------

_INTERNAL_IPS = [
    "10.0.1.15", "10.0.1.42", "10.0.2.8", "10.0.3.101", "10.0.4.22",
    "192.168.1.100", "192.168.1.105", "192.168.2.50", "192.168.10.5",
    "172.16.0.10", "172.16.0.25", "172.16.1.4",
]

_EXTERNAL_IPS = [
    "45.33.32.156", "185.220.101.34", "91.219.236.222", "23.129.64.101",
    "198.51.100.42", "203.0.113.77", "104.248.50.87", "142.250.80.46",
    "151.101.1.140", "54.239.28.85", "13.107.42.14", "31.13.71.36",
]

_DOMAINS = [
    "x7k9m.evil.com", "data-sync.cloud-api.net", "update.microsft-cdn.com",
    "cdn.legit-analytics.io", "ns1.suspicious-resolver.biz",
]

_COUNTRIES = ["Russia", "China", "North Korea", "Iran", "Brazil", "Romania", "Nigeria"]

_ESCALATION_METHODS = ["sudo exploit", "kernel CVE", "SUID binary", "token impersonation"]

_PHISHING_SUBJECTS = [
    "Urgent: Password Reset Required",
    "Invoice #38291 Attached",
    "Action Required: Account Verification",
    "RE: Meeting Tomorrow (see attachment)",
]

_FILENAMES = ["cmd.php", "c99.php", "r57.php", "webshell.aspx", "shell.jsp"]

_PROCESSES = ["xmrig", "minerd", "kworker_crypto", "svchost_miner.exe"]

_CATEGORIES = ["gambling", "adult content", "social media", "streaming"]

_SHA256_POOL = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
]


def _rand_ip(pool: list[str]) -> str:
    return random.choice(pool)


def _fill_template(template: dict) -> tuple[str, str, str, Severity]:
    """Return (alert_type, description, src_ip, severity)."""
    src_ip = _rand_ip(_INTERNAL_IPS)
    dst_ip = _rand_ip(_EXTERNAL_IPS)
    severity = random.choice(template["severities"])

    desc = template["description"].format(
        src_ip=src_ip,
        dst_ip=dst_ip,
        count=random.randint(5, 500),
        minutes=random.randint(1, 30),
        interval=random.choice([30, 60, 120, 300]),
        domain=random.choice(_DOMAINS),
        sha256=random.choice(_SHA256_POOL)[:16] + "...",
        size=random.randint(50, 5000),
        port=random.choice([4444, 8443, 8888, 9001, 1337]),
        file_count=random.randint(100, 10000),
        country=random.choice(_COUNTRIES),
        subnet=f"10.0.{random.randint(1, 10)}.0/24",
        port_count=random.randint(10, 65535),
        host_count=random.randint(5, 254),
        method=random.choice(_ESCALATION_METHODS),
        subject=random.choice(_PHISHING_SUBJECTS),
        filename=random.choice(_FILENAMES),
        src_count=random.randint(100, 50000),
        rate=random.randint(100, 10000),
        process=random.choice(_PROCESSES),
        category=random.choice(_CATEGORIES),
    )

    return template["alert_type"], desc, src_ip, dst_ip, severity


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_alert(timestamp: datetime | None = None) -> Alert:
    """Generate a single random security alert."""
    template = random.choice(_ALERT_TEMPLATES)
    alert_type, description, src_ip, dst_ip, severity = _fill_template(template)

    if timestamp is None:
        offset = random.randint(0, 300)
        timestamp = datetime.now(timezone.utc) - timedelta(seconds=offset)

    return Alert(
        id=f"ALERT-{uuid.uuid4().hex[:8].upper()}",
        source_ip=src_ip,
        dest_ip=dst_ip,
        alert_type=alert_type,
        severity=severity,
        description=description,
        timestamp=timestamp,
        status=AlertStatus.NEW,
    )


def generate_alert_batch(count: int = 20) -> list[Alert]:
    """Generate a batch of alerts spread over the last 24 hours."""
    now = datetime.now(timezone.utc)
    alerts = []
    for i in range(count):
        offset = timedelta(seconds=random.randint(0, 86400))
        ts = now - offset
        alerts.append(generate_alert(timestamp=ts))
    alerts.sort(key=lambda a: a.timestamp, reverse=True)
    return alerts


# ---------------------------------------------------------------------------
# Mock API responses (simulated security enrichment)
# ---------------------------------------------------------------------------

def mock_abuseipdb(ip: str) -> dict:
    """Simulate AbuseIPDB response."""
    score = random.randint(0, 100)
    return {
        "ip": ip,
        "abuse_confidence_score": score,
        "total_reports": random.randint(0, 500) if score > 20 else random.randint(0, 5),
        "country_code": random.choice(["US", "RU", "CN", "DE", "BR", "KR", "IR"]),
        "isp": random.choice(["DigitalOcean", "AWS", "Hetzner", "OVH", "Rostelecom"]),
        "domain": f"host-{random.randint(1,99)}.example.com",
        "is_public": True,
        "usage_type": random.choice(["Data Center/Web Hosting", "ISP", "Commercial"]),
    }


def mock_virustotal(ip: str) -> dict:
    """Simulate VirusTotal response."""
    malicious = random.randint(0, 30)
    return {
        "ip": ip,
        "malicious": malicious,
        "suspicious": random.randint(0, 10),
        "harmless": random.randint(40, 70),
        "undetected": random.randint(5, 20),
        "reputation": -malicious if malicious > 5 else random.randint(-5, 5),
        "as_owner": random.choice(["Google LLC", "Amazon.com", "Hetzner Online", "Unknown"]),
    }


def mock_otx_pulses(ip: str) -> dict:
    """Simulate AlienVault OTX response."""
    pulse_names = [
        "APT29 Cozy Bear Infrastructure",
        "Emotet Botnet C2 Nodes",
        "Cobalt Strike Beacon Servers",
        "Ransomware C2 Panel",
        "Suspicious VPN Exit Nodes",
        "Tor Exit Node List",
        "Known Malware Distribution",
    ]
    count = random.randint(0, 5)
    pulses = random.sample(pulse_names, min(count, len(pulse_names)))
    return {
        "ip": ip,
        "pulse_count": len(pulses),
        "pulses": [{"name": p, "tags": ["malware", "c2"]} for p in pulses],
    }


def mock_greynoise(ip: str) -> dict:
    """Simulate GreyNoise response."""
    classification = random.choice(["malicious", "benign", "unknown"])
    return {
        "ip": ip,
        "classification": classification,
        "noise": classification != "unknown",
        "riot": classification == "benign",
        "name": "Known Scanner" if classification == "benign" else "",
    }


def mock_nvd_cves(keyword: str) -> list[dict]:
    """Simulate NVD CVE search results."""
    cves = [
        {"id": "CVE-2024-3400", "description": "PAN-OS command injection", "cvss": 10.0, "severity": "CRITICAL"},
        {"id": "CVE-2023-44228", "description": "Log4Shell variant RCE", "cvss": 9.8, "severity": "CRITICAL"},
        {"id": "CVE-2024-21887", "description": "Ivanti Connect Secure auth bypass", "cvss": 9.1, "severity": "CRITICAL"},
        {"id": "CVE-2023-34362", "description": "MOVEit Transfer SQL injection", "cvss": 9.8, "severity": "CRITICAL"},
        {"id": "CVE-2024-1709", "description": "ConnectWise ScreenConnect auth bypass", "cvss": 10.0, "severity": "CRITICAL"},
    ]
    count = random.randint(0, 3)
    return random.sample(cves, min(count, len(cves)))


# ---------------------------------------------------------------------------
# Mock log entries (for fetch_logs tool)
# ---------------------------------------------------------------------------

def mock_siem_logs(source: str, timeframe: str) -> list[dict]:
    """Generate mock SIEM log entries."""
    log_types = [
        {"event": "AUTH_FAILURE", "message": "Failed login attempt", "user": "admin"},
        {"event": "AUTH_SUCCESS", "message": "Successful login", "user": "jsmith"},
        {"event": "FIREWALL_BLOCK", "message": "Connection blocked by firewall rule", "rule": "DENY_OUTBOUND_4444"},
        {"event": "DNS_QUERY", "message": "DNS query to suspicious domain", "domain": random.choice(_DOMAINS)},
        {"event": "FILE_WRITE", "message": "New file created in web directory", "path": f"/var/www/html/{random.choice(_FILENAMES)}"},
        {"event": "PROCESS_START", "message": "New process spawned", "process": "powershell.exe -enc BASE64..."},
        {"event": "NETWORK_CONN", "message": "Outbound connection established", "dest": f"{_rand_ip(_EXTERNAL_IPS)}:443"},
        {"event": "REGISTRY_MOD", "message": "Registry run key modified", "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
    ]

    count = random.randint(5, 15)
    now = datetime.now(timezone.utc)
    logs = []
    for i in range(count):
        entry = random.choice(log_types).copy()
        entry["timestamp"] = (now - timedelta(minutes=random.randint(0, 60))).isoformat()
        entry["source"] = source or "siem-primary"
        entry["source_ip"] = _rand_ip(_INTERNAL_IPS)
        logs.append(entry)

    logs.sort(key=lambda x: x["timestamp"], reverse=True)
    return logs
