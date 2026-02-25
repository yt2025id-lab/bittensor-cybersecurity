import random
import hashlib
from datetime import datetime, timedelta


# ============================================================
# SPECIALIZED MINERS & VALIDATORS PER THREAT TYPE
# Each threat type has its own dedicated miners with unique
# names, specialties, and analysis patterns.
# ============================================================

SPECIALISTS = {
    "malware": {
        "miners": [
            {"name": "MalwareOracle-7",    "hotkey": "5FmO7kQr", "specialty": "Behavioral Malware Analysis"},
            {"name": "RansomShield-AI",     "hotkey": "5FrS9xNp", "specialty": "Ransomware Detection"},
            {"name": "SandboxDetonator-v3", "hotkey": "5FsD3vLm", "specialty": "Dynamic Sandbox Analysis"},
            {"name": "C2-Hunter-Pro",       "hotkey": "5Fc2HpWq", "specialty": "C2 Communication Detection"},
            {"name": "PEAnalyzer-Deep",     "hotkey": "5FpA8dKs", "specialty": "Static PE File Analysis"},
            {"name": "EDR-Sentinel-X",      "hotkey": "5FeS4xTn", "specialty": "Endpoint Threat Detection"},
        ],
        "validators": [
            {"name": "MalwareDB-Verifier",   "hotkey": "5VmD1bRt", "specialty": "VirusTotal / MalwareBazaar cross-check"},
            {"name": "YARA-RuleChecker",      "hotkey": "5VyR2cHk", "specialty": "YARA signature matching"},
            {"name": "Sandbox-Validator-01",  "hotkey": "5VsV3dPn", "specialty": "Sandbox behavior verification"},
            {"name": "ThreatIntel-Oracle",    "hotkey": "5VtI4eQm", "specialty": "Threat intelligence feed correlation"},
        ],
        "check_labels": ["Signature Match", "Sandbox Verified", "C2 IP Blacklisted"],
        "analyses": [
            "Detected Trojan variant using behavioral heuristics. Process injection into svchost.exe confirmed via API hooking. Recommend immediate network isolation of affected host.",
            "Signature match with LockBit 3.0 ransomware family. Shadow copy deletion via vssadmin detected. Lateral movement via SMB observed on port 445 targeting domain controller.",
            "Identified C2 beacon to 194.26.29.x range with 60-second interval. Persistence via HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. Binary packed with UPX — high evasion score.",
            "Malware sandbox detonation (30s runtime) reveals credential harvesting module targeting Chrome/Firefox. Data exfiltration channel: DNS TXT record tunneling to attacker domain.",
            "Static analysis: PE32 executable with stolen Authenticode certificate (revoked). Anti-VM checks via CPUID instruction. Drops secondary payload from encrypted resource section.",
            "EDR telemetry shows process chain: outlook.exe → cmd.exe → powershell.exe → encoded payload. AMSI bypass technique detected. Fileless execution in memory confirmed.",
        ],
    },
    "phishing": {
        "miners": [
            {"name": "PhishNet-Guard",      "hotkey": "5FpG1nRt", "specialty": "Email Header Analysis"},
            {"name": "EmailForensic-AI",     "hotkey": "5FeF2oSk", "specialty": "Email Forensics & DMARC"},
            {"name": "URLScanner-Deep",      "hotkey": "5FuS3pTn", "specialty": "Malicious URL Detection"},
            {"name": "BEC-Detector-v4",      "hotkey": "5FbD4qUm", "specialty": "Business Email Compromise"},
            {"name": "DomainWatch-Pro",      "hotkey": "5FdW5rVl", "specialty": "Lookalike Domain Detection"},
            {"name": "CredHarvest-Hunter",   "hotkey": "5FcH6sWk", "specialty": "Credential Phishing Kit Analysis"},
        ],
        "validators": [
            {"name": "DMARC-Validator",       "hotkey": "5VdM1aXp", "specialty": "SPF/DKIM/DMARC record verification"},
            {"name": "URLhaus-Checker",       "hotkey": "5VuH2bYq", "specialty": "URLhaus / PhishTank database check"},
            {"name": "DomainAge-Verifier",    "hotkey": "5VdA3cZr", "specialty": "WHOIS domain age verification"},
            {"name": "EmailReputation-Node",  "hotkey": "5VeR4dAs", "specialty": "Sender reputation scoring"},
        ],
        "check_labels": ["DMARC/SPF Failed", "URL in PhishTank", "Domain Age < 7 days"],
        "analyses": [
            "Email header deep-dive: Return-Path mismatch with From header. SPF result=fail, DKIM signature absent. Received chain shows relay through bulletproof hosting (AS48666) in Moldova.",
            "URL sandbox analysis: landing page is pixel-perfect clone of Microsoft 365 login. JavaScript keylogger captures keystrokes in real-time. Harvested credentials POST to /api/collect on attacker server.",
            "BEC pattern confirmed: Display name matches CEO but Reply-To points to external Gmail. Language analysis reveals urgency markers ('immediately', 'confidential', 'today'). Wire transfer to new account.",
            "Attachment analysis: macro-enabled .xlsm file. VBA macro uses WMI to spawn PowerShell with encoded command. Downloads Cobalt Strike stager from compromised WordPress site (hxxps://legit-blog[.]com/wp-content/upload.php).",
            "Lookalike domain: 'ourcompany-secure.com' registered via Namecheap 36 hours ago. Uses homoglyph 'а' (Cyrillic) in subdomain. SSL cert from Let's Encrypt. MX records point to Yandex mail servers.",
            "Credential phishing kit identified as 'Kr3pto' variant. Targets banking credentials with real-time OTP relay to attacker. Exfil via Telegram Bot API (token extracted from source).",
        ],
    },
    "ddos": {
        "miners": [
            {"name": "TrafficAnalyzer-Pro",  "hotkey": "5FtA1nRq", "specialty": "Volumetric Traffic Analysis"},
            {"name": "DDoS-Fingerprint-AI",  "hotkey": "5FdF2oSm", "specialty": "Attack Vector Fingerprinting"},
            {"name": "NetFlow-Scanner-v2",   "hotkey": "5FnS3pTk", "specialty": "NetFlow/sFlow Analysis"},
            {"name": "BGP-Monitor-Node",     "hotkey": "5FbM4qUn", "specialty": "BGP Route Monitoring"},
            {"name": "Amplification-Hunter", "hotkey": "5FaH5rVp", "specialty": "Amplification Attack Detection"},
        ],
        "validators": [
            {"name": "NetFlow-Validator",     "hotkey": "5VnV1aXq", "specialty": "Traffic baseline comparison"},
            {"name": "ISP-Feed-Checker",      "hotkey": "5ViF2bYm", "specialty": "ISP threat intelligence feed"},
            {"name": "BGP-Anomaly-Verifier",  "hotkey": "5VbA3cZk", "specialty": "BGP route anomaly verification"},
        ],
        "check_labels": ["Traffic Baseline Exceeded", "Source IP Spoofed", "Amplification Confirmed"],
        "analyses": [
            "Volumetric analysis: 47.3 Gbps inbound UDP flood from 12,847 unique source IPs across 43 ASNs. Peak PPS: 8.2M packets/sec. Amplification via open memcached reflectors (port 11211).",
            "SYN flood fingerprint: 2.1M SYN packets/sec with randomized source IPs (TTL analysis confirms spoofing). TCP stack on primary LB at 94% connection table capacity. Imminent service degradation.",
            "HTTP/2 Rapid Reset attack (CVE-2023-44487) detected. 856,000 concurrent streams/sec targeting /api/v2/* endpoints. Bypassing rate limiter via H2 stream multiplexing. Origin server CPU at 98%.",
            "DNS amplification: average response factor 54x. 2,340 open resolvers abused, predominantly in AS4134 (China Telenet) and AS9121 (Turkey Telekom). Recommend upstream blackhole for affected /24.",
            "Multi-vector attack: Layer 3 UDP flood + Layer 7 HTTP POST flood running simultaneously. Bot signatures match Mirai variant. GeoIP: 67% South America, 22% Southeast Asia, 11% Eastern Europe.",
        ],
    },
    "sql injection": {
        "miners": [
            {"name": "SQLi-Detective-Pro",   "hotkey": "5FsD1nRp", "specialty": "SQL Injection Pattern Analysis"},
            {"name": "WAF-LogAnalyzer-v3",   "hotkey": "5FwL2oSn", "specialty": "WAF Log Forensics"},
            {"name": "DBForensic-AI",        "hotkey": "5FdF3pTm", "specialty": "Database Activity Forensics"},
            {"name": "PayloadDecoder-X",     "hotkey": "5FpD4qUl", "specialty": "Encoded Payload Decoding"},
            {"name": "OWASP-Scanner-Node",   "hotkey": "5FoS5rVk", "specialty": "OWASP Top 10 Scanning"},
        ],
        "validators": [
            {"name": "SQLi-Signature-Check",  "hotkey": "5VsS1aXn", "specialty": "Known SQLi pattern matching"},
            {"name": "CVE-DB-Validator",       "hotkey": "5VcD2bYl", "specialty": "CVE database cross-reference"},
            {"name": "WAF-Rule-Verifier",      "hotkey": "5VwR3cZk", "specialty": "WAF rule effectiveness verification"},
        ],
        "check_labels": ["SQLi Pattern Confirmed", "CVE Matched", "Data Exfil Detected"],
        "analyses": [
            "UNION-based SQLi confirmed on /api/users/login (POST 'username' param). Attacker extracted 'users' table: 14,832 rows including bcrypt password hashes. Attack tool: sqlmap v1.7.12 (User-Agent fingerprint).",
            "Time-based blind injection on /search?q= parameter. Payload: ' AND SLEEP(5)-- confirmed 5.02s delay. Database: PostgreSQL 14.8. Attacker systematically enumerating information_schema.tables.",
            "Second-order SQLi: malicious payload stored in user profile 'bio' field ('); DROP TABLE sessions;--). Triggers when admin views user list. WAF bypassed via double URL encoding (%2527).",
            "Error-based extraction: verbose MySQL error messages leaking database structure. Attacker used EXTRACTVALUE() and UPDATEXML() functions. 15 vulnerable endpoints identified across /api/v1/* and /api/v2/*.",
            "Automated attack from 847 rotating residential proxies (luminati.io fingerprint). Payload variations include: UNION SELECT, boolean-based blind, stacked queries. Rate: 2,100 requests/min for 6+ hours.",
        ],
    },
    "zero-day": {
        "miners": [
            {"name": "ZeroDay-Hunter-X",     "hotkey": "5FzH1nRn", "specialty": "Zero-Day Exploit Detection"},
            {"name": "APT-Tracker-Pro",      "hotkey": "5FaT2oSm", "specialty": "APT Campaign Tracking"},
            {"name": "ExploitChain-AI",      "hotkey": "5FeC3pTl", "specialty": "Exploit Chain Analysis"},
            {"name": "FirmwareAudit-Node",   "hotkey": "5FfA4qUk", "specialty": "Firmware Vulnerability Audit"},
            {"name": "ThreatIntel-Deep",     "hotkey": "5FtI5rVn", "specialty": "Dark Web Threat Intelligence"},
        ],
        "validators": [
            {"name": "Exploit-DB-Verifier",   "hotkey": "5VeD1aXm", "specialty": "Exploit-DB / NVD correlation"},
            {"name": "APT-Attribution-Node",  "hotkey": "5VaA2bYk", "specialty": "APT group TTP attribution"},
            {"name": "Patch-Gap-Checker",     "hotkey": "5VpG3cZn", "specialty": "Vendor patch availability check"},
        ],
        "check_labels": ["Exploit Reproduced", "APT TTP Matched", "Vendor Notified"],
        "analyses": [
            "Unknown exploit targeting unpatched vulnerability in Fortinet FortiOS. RCE achieved via crafted HTTP/3 QUIC packet to management interface. No public PoC or CVE assigned yet. CVSS estimate: 9.8.",
            "Novel privilege escalation chain: userland heap overflow → kernel arbitrary write via io_uring → SYSTEM shell. Bypasses latest KASLR and CFI mitigations on Windows 11 23H2.",
            "Zero-day in Palo Alto PAN-OS GlobalProtect VPN. Unauthenticated RCE via path traversal + command injection in /ssl-vpn/hipreport.esp. Exploit delivered via crafted IKEv2 packet.",
            "APT-29 (Cozy Bear) TTP fingerprint. Previously unknown Java deserialization vuln in Apache middleware. Cobalt Strike 4.9 beacon with custom malleable C2 profile. Sleep time: 45min jitter.",
            "Firmware-level rootkit discovered in network switch UEFI. Survives factory reset. Exfiltrates traffic via covert DNS channel. Attribution: possibly state-sponsored (CN-based infrastructure).",
        ],
    },
    "insider threat": {
        "miners": [
            {"name": "UEBA-Sentinel-v4",    "hotkey": "5FuS1nRm", "specialty": "User Behavior Analytics"},
            {"name": "DLP-Monitor-Pro",      "hotkey": "5FdM2oSl", "specialty": "Data Loss Prevention"},
            {"name": "AccessAudit-AI",       "hotkey": "5FaA3pTk", "specialty": "Access Pattern Auditing"},
            {"name": "PrivEsc-Detector-X",   "hotkey": "5FpD4qUn", "specialty": "Privilege Escalation Detection"},
            {"name": "ExfilWatch-Node",      "hotkey": "5FeW5rVm", "specialty": "Data Exfiltration Monitoring"},
        ],
        "validators": [
            {"name": "HR-Data-Correlator",    "hotkey": "5VhD1aXl", "specialty": "HR event correlation (resignation/termination)"},
            {"name": "AccessLog-Auditor",     "hotkey": "5VaL2bYk", "specialty": "Access log anomaly verification"},
            {"name": "DLP-Policy-Checker",    "hotkey": "5VdP3cZn", "specialty": "DLP policy violation confirmation"},
        ],
        "check_labels": ["Behavior Anomaly Confirmed", "HR Event Correlated", "DLP Violation Logged"],
        "analyses": [
            "UEBA alert: User 'jsmith' downloaded 2.3 GB from SharePoint between 2:14-3:47 AM (EST). Historical baseline: 50 MB/day. Files include Q4 financial reports, customer PII export, and board meeting minutes.",
            "Privileged account 'db_admin_02' used to export full customer database (847,000 records) via SQL Server Management Studio at 11:23 PM. HR confirms: employee submitted resignation notice 3 days prior.",
            "USB mass storage (SanDisk Ultra 128GB, S/N: 4C530001211024) connected to finance workstation WS-FIN-042. 847 files copied including M&A due diligence documents and salary spreadsheets.",
            "Abnormal email forwarding rule detected on CFO mailbox: all emails containing keywords 'confidential', 'board', 'acquisition' auto-forwarded to external Gmail (throwaway4829@gmail.com) created yesterday.",
            "Cloud DLP triggered: user uploaded 312 files (1.8 GB) to personal Google Drive via Chrome browser. Files include source code from /internal-tools repo and API keys from .env files.",
        ],
    },
}


THREAT_DATABASE = {
    "malware": {
        "variants": [
            {
                "risk_level": "Critical",
                "risk_score": 92,
                "threat_name": "Trojan.GenericKD.46789",
                "category": "Malware",
                "mitigation": "1. Immediately isolate affected systems from the network.\n2. Run full antivirus scan with updated definitions.\n3. Check for persistence mechanisms in registry and scheduled tasks.\n4. Review outbound network connections for C2 communication.\n5. Restore from clean backup if system integrity is compromised.",
                "recommendation": "Deploy EDR solution across all endpoints. Implement application whitelisting. Enable real-time behavioral analysis.",
                "indicators": ["Suspicious process spawning", "Registry modification", "Outbound connection to known C2 IP", "File encryption activity"],
                "affected_systems": ["Windows Endpoints", "Active Directory"],
                "cve_references": ["CVE-2024-21412", "CVE-2023-44487"],
            },
            {
                "risk_level": "High",
                "risk_score": 78,
                "threat_name": "Ransomware.LockBit3.0",
                "category": "Malware - Ransomware",
                "mitigation": "1. Enable Volume Shadow Copy protection.\n2. Implement network segmentation to limit lateral movement.\n3. Deploy anti-ransomware tools with behavioral detection.\n4. Ensure offline backups are current and tested.\n5. Block known ransomware file extensions at email gateway.",
                "recommendation": "Implement Zero Trust Architecture. Regular backup testing. User awareness training on phishing vectors.",
                "indicators": ["Mass file renaming", "Deletion of shadow copies", "Ransom note creation", "Lateral movement via SMB"],
                "affected_systems": ["Windows Servers", "NAS Storage", "Shared Drives"],
                "cve_references": ["CVE-2024-1709", "CVE-2023-4966"],
            },
        ],
    },
    "phishing": {
        "variants": [
            {
                "risk_level": "High",
                "risk_score": 75,
                "threat_name": "Spear-Phishing Campaign #SPH-2024",
                "category": "Social Engineering",
                "mitigation": "1. Implement DMARC, DKIM, and SPF email authentication.\n2. Deploy advanced email filtering with URL sandboxing.\n3. Enable multi-factor authentication on all accounts.\n4. Train employees on phishing identification.\n5. Set up automated phishing simulation exercises.",
                "recommendation": "Deploy browser isolation for email links. Implement conditional access policies. Regular phishing simulation tests.",
                "indicators": ["Spoofed sender domain", "Urgency-based language", "Credential harvesting URL", "Lookalike domain registration"],
                "affected_systems": ["Email Gateway", "User Credentials", "Cloud Services"],
                "cve_references": ["CVE-2024-21413", "CVE-2023-35636"],
            },
            {
                "risk_level": "Medium",
                "risk_score": 58,
                "threat_name": "Business Email Compromise (BEC)",
                "category": "Social Engineering - BEC",
                "mitigation": "1. Implement strict email forwarding rules.\n2. Verify wire transfer requests through secondary channel.\n3. Deploy AI-based email anomaly detection.\n4. Review mailbox rules for unauthorized forwarding.\n5. Implement domain-based message authentication.",
                "recommendation": "Establish out-of-band verification for financial transactions. Regular audit of email forwarding rules. Executive account protection.",
                "indicators": ["CEO impersonation", "Unusual wire transfer request", "Domain typosquatting", "Mailbox rule manipulation"],
                "affected_systems": ["Email System", "Financial Systems", "Executive Accounts"],
                "cve_references": [],
            },
        ],
    },
    "ddos": {
        "variants": [
            {
                "risk_level": "High",
                "risk_score": 82,
                "threat_name": "Volumetric DDoS - UDP Flood",
                "category": "Denial of Service",
                "mitigation": "1. Enable DDoS protection service (e.g., Cloudflare, AWS Shield).\n2. Configure rate limiting on edge routers.\n3. Implement anycast network distribution.\n4. Set up traffic scrubbing centers.\n5. Establish incident response runbook for DDoS events.",
                "recommendation": "Deploy Web Application Firewall (WAF). Implement traffic baseline monitoring. Establish ISP-level blackhole routing agreements.",
                "indicators": ["Sudden traffic spike >500%", "UDP flood from multiple sources", "SYN flood pattern", "Amplification attack vectors"],
                "affected_systems": ["Web Servers", "DNS Infrastructure", "Load Balancers"],
                "cve_references": ["CVE-2023-44487"],
            },
        ],
    },
    "sql injection": {
        "variants": [
            {
                "risk_level": "Critical",
                "risk_score": 95,
                "threat_name": "SQL Injection - Union Based",
                "category": "Web Application Attack",
                "mitigation": "1. Implement parameterized queries/prepared statements.\n2. Deploy Web Application Firewall with SQL injection rules.\n3. Apply input validation and sanitization.\n4. Use least-privilege database accounts.\n5. Enable database activity monitoring and alerting.",
                "recommendation": "Conduct full application security audit. Implement OWASP Top 10 protections. Regular penetration testing schedule.",
                "indicators": ["Unusual SQL error messages", "Database enumeration attempts", "UNION SELECT patterns in logs", "Time-based blind injection probes"],
                "affected_systems": ["Web Application", "Database Server", "API Endpoints"],
                "cve_references": ["CVE-2024-23897", "CVE-2023-50164"],
            },
        ],
    },
    "zero-day": {
        "variants": [
            {
                "risk_level": "Critical",
                "risk_score": 98,
                "threat_name": "Zero-Day Exploit - Remote Code Execution",
                "category": "Advanced Persistent Threat",
                "mitigation": "1. Apply emergency virtual patching via WAF/IPS.\n2. Implement network micro-segmentation.\n3. Enable enhanced logging and monitoring.\n4. Restrict outbound connections from affected systems.\n5. Coordinate with vendor for emergency patch.",
                "recommendation": "Implement defense-in-depth strategy. Deploy deception technology (honeypots). Enable threat hunting operations.",
                "indicators": ["Unknown exploit signature", "Anomalous process behavior", "Unexpected privilege escalation", "Novel C2 communication pattern"],
                "affected_systems": ["Varies - Check vendor advisory"],
                "cve_references": ["Pending CVE Assignment"],
            },
        ],
    },
    "insider threat": {
        "variants": [
            {
                "risk_level": "High",
                "risk_score": 80,
                "threat_name": "Insider Threat - Data Exfiltration",
                "category": "Insider Threat",
                "mitigation": "1. Implement Data Loss Prevention (DLP) solution.\n2. Enable User and Entity Behavior Analytics (UEBA).\n3. Restrict USB and removable media access.\n4. Monitor cloud storage uploads and email attachments.\n5. Implement privileged access management (PAM).",
                "recommendation": "Deploy zero-trust access controls. Regular access reviews. Implement separation of duties for sensitive operations.",
                "indicators": ["Unusual data download volume", "Access outside business hours", "Bulk file copying to removable media", "Unauthorized cloud storage uploads"],
                "affected_systems": ["Endpoints", "Cloud Storage", "Database Systems", "Email"],
                "cve_references": [],
            },
        ],
    },
}

DEFAULT_RESPONSE = {
    "risk_level": "Medium",
    "risk_score": 55,
    "threat_name": "Unclassified Threat",
    "category": "General Threat",
    "mitigation": "1. Conduct thorough investigation of the reported activity.\n2. Review system and network logs for anomalies.\n3. Update all security signatures and patches.\n4. Enable enhanced monitoring on affected systems.\n5. Escalate to incident response team if needed.",
    "recommendation": "Implement comprehensive security monitoring. Regular vulnerability assessments. Update incident response procedures.",
    "indicators": ["Requires further analysis", "Monitor for recurring patterns"],
    "affected_systems": ["Requires assessment"],
    "cve_references": [],
}


def _generate_miner_responses(threat_type, variant, num_miners=5):
    """Generate specialized miner responses per threat type."""
    spec = SPECIALISTS.get(threat_type, SPECIALISTS["malware"])

    pool = spec["miners"]
    num = min(num_miners, len(pool))
    selected = random.sample(pool, num)
    analyses = spec["analyses"]
    used_analyses = random.sample(analyses, min(num, len(analyses)))

    miners = []
    for i, miner in enumerate(selected):
        score = round(random.uniform(0.68, 0.96), 4)
        response_time = round(random.uniform(0.4, 2.6), 2)

        # Top miner gets best score
        if i == 0:
            score = round(random.uniform(0.93, 0.99), 4)
            response_time = round(random.uniform(0.2, 0.8), 2)

        hk = miner["hotkey"]
        miners.append({
            "uid": random.randint(1, 255),
            "hotkey": f"{hk}...{hashlib.md5(hk.encode()).hexdigest()[:6]}",
            "name": miner["name"],
            "specialty": miner["specialty"],
            "score": score,
            "response_time_s": response_time,
            "risk_assessed": variant["risk_level"],
            "analysis": used_analyses[i] if i < len(used_analyses) else random.choice(analyses),
            "rank": i + 1,
        })

    miners.sort(key=lambda m: m["score"], reverse=True)
    for i, m in enumerate(miners):
        m["rank"] = i + 1

    return miners


def _generate_validator_results(threat_type, num_validators=3):
    """Generate specialized validator results per threat type."""
    spec = SPECIALISTS.get(threat_type, SPECIALISTS["malware"])

    pool = spec["validators"]
    num = min(num_validators, len(pool))
    selected = random.sample(pool, num)
    check_labels = spec["check_labels"]

    validators = []
    for val in selected:
        hk = val["hotkey"]
        stake = round(random.uniform(1200, 15000), 2)
        vtrust = round(random.uniform(0.87, 0.99), 4)

        checks = {}
        checks_passed = 0
        for label in check_labels:
            passed = random.choice([True, True, True, False])
            checks[label] = passed
            if passed:
                checks_passed += 1

        validators.append({
            "uid": random.randint(1, 64),
            "hotkey": f"{hk}...{hashlib.md5(hk.encode()).hexdigest()[:6]}",
            "name": val["name"],
            "specialty": val["specialty"],
            "stake_tao": stake,
            "vtrust": vtrust,
            "checks_passed": checks_passed,
            "checks_total": len(check_labels),
            "check_details": checks,
            "consensus": "Approved" if checks_passed >= 2 else "Disputed",
        })

    return validators


def get_cybersecurity_advice(query):
    """Analyze threat and return comprehensive cybersecurity advice with miner/validator data."""
    threat_type = query.threat_type.lower().strip()
    description = query.description.lower().strip()

    matched_key = None
    matched = None
    for key in THREAT_DATABASE:
        if key in threat_type or key in description:
            matched_key = key
            matched = THREAT_DATABASE[key]
            break

    if matched:
        variant = random.choice(matched["variants"])
    else:
        matched_key = "malware"
        variant = DEFAULT_RESPONSE.copy()

    analysis_time = round(random.uniform(0.8, 2.5), 2)
    confidence = random.randint(85, 99)

    num_miners = random.randint(4, 6)
    num_validators = random.randint(2, 4)
    miner_responses = _generate_miner_responses(matched_key, variant, num_miners)
    validator_results = _generate_validator_results(matched_key, num_validators)

    total_tao = round(random.uniform(0.05, 0.35), 4)

    return {
        "risk_level": variant["risk_level"],
        "risk_score": variant.get("risk_score", 55),
        "threat_name": variant.get("threat_name", "Unknown"),
        "category": variant.get("category", "General"),
        "mitigation": variant["mitigation"],
        "recommendation": variant["recommendation"],
        "indicators": variant.get("indicators", []),
        "affected_systems": variant.get("affected_systems", []),
        "cve_references": variant.get("cve_references", []),
        "analysis_time_seconds": analysis_time,
        "confidence_score": confidence,
        "miner_nodes_consulted": len(miner_responses),
        "validator_nodes_consulted": len(validator_results),
        "miner_responses": miner_responses,
        "validator_results": validator_results,
        "tao_reward_pool": total_tao,
        "consensus_reached": True,
        "block_number": random.randint(3_800_000, 4_200_000),
        "timestamp": datetime.utcnow().isoformat(),
        "subnet_version": "1.0.0-beta",
    }


def get_dashboard_stats():
    return {
        "threats_analyzed_today": random.randint(1200, 2500),
        "threats_blocked": random.randint(800, 1800),
        "active_miners": random.randint(120, 256),
        "active_validators": random.randint(30, 64),
        "avg_response_time_ms": random.randint(180, 450),
        "network_uptime_percent": round(random.uniform(99.5, 99.99), 2),
        "total_tao_distributed": round(random.uniform(1200, 3500), 2),
    }


def get_live_feed(count=5):
    LIVE_THREATS = [
        {"source_ip": "185.220.101.34", "country": "Russia", "type": "Brute Force SSH", "severity": "High", "target": "Production Server"},
        {"source_ip": "45.155.205.99", "country": "Netherlands", "type": "SQL Injection Attempt", "severity": "Critical", "target": "Web Application"},
        {"source_ip": "194.26.29.12", "country": "Romania", "type": "Malware C2 Communication", "severity": "Critical", "target": "Endpoint WS-0142"},
        {"source_ip": "91.243.44.51", "country": "Ukraine", "type": "DDoS SYN Flood", "severity": "High", "target": "Load Balancer"},
        {"source_ip": "5.188.206.14", "country": "Russia", "type": "Ransomware Beacon", "severity": "Critical", "target": "File Server"},
    ]
    selected = random.sample(LIVE_THREATS, min(count, len(LIVE_THREATS)))
    feed = []
    for threat in selected:
        entry = threat.copy()
        entry["timestamp"] = (datetime.utcnow() - timedelta(seconds=random.randint(1, 300))).isoformat()
        entry["id"] = f"THR-{random.randint(100000, 999999)}"
        entry["status"] = random.choice(["Blocked", "Monitoring", "Investigating"])
        feed.append(entry)
    return feed
