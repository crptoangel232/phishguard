# PhishGuard — Security Suite

> 10 cybersecurity tools in one Python suite. AI phishing detection, network scanning, log analysis, IOC scanning, forensic timeline, IR playbooks, and a mini-SIEM.

PhishGuard is a comprehensive Python-based cybersecurity toolkit covering ethical hacking, SOC analysis, incident response, and SIEM operations. Built for security professionals, researchers, and developers who need to assess and respond to security threats.

## 🔧 10 Tools in One Suite

### Ethical Hacking
1. **Phishing URL Detector** — 18 URL features analyzed by a Random Forest ML model with real-time risk scoring
2. **Network Port Scanner** — Scans 68 common ports, detects services, grabs banners, flags vulnerabilities
3. **Password Strength Auditor** — Entropy analysis, crack-time estimation (GPU scenarios), pattern detection, policy recommendations
4. **SQL Injection & XSS Detector** — Tests 15 SQLi + 15 XSS payloads, detects injection points, checks security headers

### SOC Analysis
5. **Log Analyzer & Threat Correlator** — Parses SSH/Apache/Windows logs, detects brute-force, impossible travel, privilege escalation, correlates attack chains
6. **IOC Scanner** — Checks IPs, domains, file hashes, and URLs against threat intelligence with typosquatting detection

### Incident Response
7. **Forensic Timeline Builder** — Maps events to Lockheed Martin Kill Chain and MITRE ATT&CK framework, generates attack narrative
8. **IR Playbook Engine** — NIST SP 800-61 compliant response procedures for 8 incident types (phishing, ransomware, malware, data breach, brute force, web attack, insider threat, network scan)

### SIEM
9. **Mini-SIEM Dashboard** — Central log aggregation with 10 correlation rules, real-time alerting, threat-level dashboard, top source IPs, event feed
10. **Alert Correlation Engine** — Deduplication, aggregation, kill chain progression grouping, reduces alert fatigue with intelligent incident grouping

## 🛡️ Detection Capabilities

### Phishing Detection (18 URL Features)
URL Length, Domain Length, IP Detection, @ Symbol, HTTPS, Dots, Dashes, Subdomains, Suspicious TLD, Port, Query Params, Path Length, Double Slash, Suspicious Keywords, Hex Encoding, Digit Ratio, Punycode, Entropy

### Network Scanner (68 Ports)
High Risk: Telnet(23), SMB(445), MSSQL(1433), Docker API(2375), RDP(3389), PostgreSQL(5432), VNC(5900), Redis(6379), Elasticsearch(9200), MongoDB(27017), Memcached(11211)
Medium Risk: FTP(21), HTTP(80), POP3(110), SNMP(161), Dev Servers(3000/5000/8080)
Low Risk: SSH(22), HTTPS(443), SMTPS(465), IMAPS(993), POP3S(995)

### MITRE ATT&CK Techniques Mapped
T1110 (Brute Force), T1078 (Valid Accounts), T1059 (Command Execution), T1046 (Network Scan), T1190 (Exploit App), T1071 (C2 Protocol), T1041 (Exfiltration), T1486 (Ransomware), T1003 (Credential Dumping), T1098 (Account Manipulation), T1087 (Account Discovery)

## 📦 Installation

```bash
git clone https://github.com/crptoangel232/phishguard.git
cd phishguard
pip install -r requirements.txt
python model.py    # Train the phishing detection model
python app.py      # Start the security suite
```

Open `http://localhost:5000`

## 🏗 Architecture

```
phishguard/
├── app.py                  # Flask server with all 10 API endpoints
├── model.py                # ML model training (Random Forest)
├── features.py             # URL feature extraction (18 features)
├── scanner.py              # Network port scanner (68 ports, socket + threading)
├── password_auditor.py     # Password strength analysis + crack-time
├── sqli_detector.py        # SQL injection & XSS detection
├── log_analyzer.py         # Log parsing + threat correlation
├── ioc_scanner.py          # IOC reputation checking (IP, domain, hash, URL)
├── forensic_timeline.py    # Kill chain + MITRE ATT&CK mapping
├── ir_playbook.py          # NIST SP 800-61 incident response playbooks
├── siem_engine.py          # Mini-SIEM with 10 correlation rules
├── alert_correlation.py    # Alert deduplication + incident grouping
├── templates/index.html    # Web UI
├── static/css/style.css    # Dark cybersecurity theme
├── static/js/app.js        # Frontend logic
├── docs/index.html         # GitHub Pages live demo
└── README.md
```

## 🌐 Live Demo

https://crptoangel232.github.io/phishguard/

## 🧪 Example Results

1. **Phishing**: `http://paypal-secure-login.tk/account/verify` → 99% risk, PHISHING
2. **Password Audit**: `Summer2024!` → 79/100 (Strong), 72 bits entropy, crack time: millions of years
3. **IOC Scan**: `185.220.101.45` → Malicious (Known Tor exit node)
4. **Log Analysis**: 5 failed logins + 1 success → CRITICAL, brute-force attack chain detected
5. **Forensic Timeline**: Maps to MITRE T1110 (Brute Force) → T1078 (Valid Accounts) → T1059 (Command Execution)
6. **IR Playbook**: Ransomware → 6-phase NIST playbook with 28 steps, immediate isolation as quick action
7. **SIEM Dashboard**: 3 alerts (brute force, successful login after brute force, impossible travel) → CRITICAL
8. **Alert Correlation**: 3 raw alerts → 2 incidents (aggregated + standalone), immediate block recommendation

## 📌 Project Info

- **Builder:** Albert Cho Taylor
- **Domain:** Cybersecurity + AI
- **Contact:** 076988619 · hawakharb@gmail.com

---

⚠️ **Disclaimer:** This tool is for educational and authorized security testing only. Always scan targets you own or have explicit permission to test.
