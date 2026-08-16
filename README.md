# PhishGuard — Security Suite

> AI phishing URL detection + network security scanner. Two cybersecurity tools in one Python suite.

PhishGuard is a Python-based security toolkit that combines phishing URL detection using machine learning with network port scanning and vulnerability assessment. Built for cybersecurity professionals, researchers, and developers who need to assess security threats quickly.

## 🔍 Two Tools, One Suite

### 1. Phishing URL Detector
- **18 URL Features** — IP detection, HTTPS status, suspicious keywords, entropy, punycode, TLD analysis, and more
- **Random Forest ML Model** — Trained on phishing and legitimate URL patterns with scikit-learn
- **Real-time Risk Scoring** — 0-100% risk score with LOW / MEDIUM / HIGH classification
- **Feature Breakdown** — See exactly which features triggered the detection and why

### 2. Network Security Scanner
- **68 Common Ports** — Scans FTP, SSH, HTTP, HTTPS, MySQL, Redis, MongoDB, RDP, Docker, and more
- **Service Detection** — Identifies the service running on each open port
- **Banner Grabbing** — Captures service banners for fingerprinting
- **Vulnerability Assessment** — Flags known vulnerabilities per port with remediation guidance
- **Risk Scoring** — Overall risk score (CRITICAL / HIGH / MEDIUM / LOW / MINIMAL) based on exposed services
- **Concurrent Scanning** — Uses ThreadPoolExecutor for fast multi-port scanning

## 🛡️ Features Detected

### Phishing Detection (18 URL Features)
| # | Feature | Description |
|---|---------|-------------|
| 1 | URL Length | Phishing URLs tend to be longer than legitimate ones |
| 2 | Domain Length | Unusually long domains can indicate phishing |
| 3 | Has IP Address | Using an IP instead of a domain name is a phishing indicator |
| 4 | Has @ Symbol | Everything before @ is ignored in URLs |
| 5 | Uses HTTPS | Legitimate sites typically use HTTPS encryption |
| 6 | Number of Dots | Excessive dots suggest many subdomains (phishing pattern) |
| 7 | Number of Dashes | Dashes are common in phishing URLs to mimic brands |
| 8 | Number of Subdomains | Multiple subdomains can indicate phishing |
| 9 | Suspicious TLD | TLDs like .tk, .ml, .ga, .cf are associated with phishing |
| 10 | Has Port | Non-standard ports in URLs are suspicious |
| 11 | Query Parameters | Excessive parameters can indicate tracking or phishing |
| 12 | Path Length | Long paths can hide the true destination |
| 13 | Double Slash Redirect | // in path can indicate redirect attempts |
| 14 | Suspicious Keywords | Words like "login", "verify", "paypal", "free", "gift" |
| 15 | Hex Encoding | %XX encoded characters can hide malicious content |
| 16 | Digit-to-Letter Ratio | High digit ratio in domain is suspicious |
| 17 | Punycode/IDN | Internationalized domain names enable homograph attacks |
| 18 | URL Entropy | High entropy suggests randomly generated URLs |

### Network Scanner (68 Ports Monitored)
| Risk Level | Ports | Examples |
|------------|-------|----------|
| HIGH | 23, 445, 1433, 2375, 3389, 5432, 5900, 6379, 9200, 11211, 27017 | Telnet, SMB, MSSQL, Docker API, RDP, PostgreSQL, VNC, Redis, Elasticsearch, Memcached, MongoDB |
| MEDIUM | 21, 80, 110, 161, 5000, 8080, 3000, 8000 | FTP, HTTP, POP3, SNMP, Dev servers |
| LOW | 22, 443, 465, 587, 636, 993, 995 | SSH, HTTPS, SMTPS, IMAPS, POP3S |

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/crptoangel232/phishguard.git
cd phishguard

# Install dependencies
pip install -r requirements.txt

# Train the phishing detection model (first run only)
python model.py

# Start the security suite server
python app.py
```

The suite will be available at `http://localhost:5000`

- Tab 1: Phishing URL Detector
- Tab 2: Network Security Scanner

## 🏗 Architecture

```
phishguard/
├── app.py              # Flask web server (phishing API + scanner API)
├── model.py            # ML model training (Random Forest with scikit-learn)
├── features.py         # URL feature extraction (18 features)
├── scanner.py          # Network scanner (port scan, service detection, vuln assessment)
├── phishing_model.joblib  # Trained model (generated on first run)
├── requirements.txt    # Python dependencies
├── templates/
│   └── index.html      # Web UI with tabs for both tools
├── static/
│   ├── css/style.css   # Dark cybersecurity theme
│   └── js/app.js       # Frontend logic for both tools
├── docs/
│   └── index.html      # GitHub Pages live demo
└── README.md
```

## 🔧 How It Works

### Phishing Detection
```
URL Input → Feature Extraction (18 features) → Random Forest Model → Risk Score + Breakdown
```

### Network Scanning
```
Target Input → DNS Resolution → Concurrent Port Scan (68 ports) → Service Detection + Banner Grabbing → Vulnerability Assessment → Security Report
```

## 🧪 Example Results

### Phishing Detection
**Legitimate URL:** `https://www.google.com/search?q=hello`
- Risk Score: 0% — Verdict: SAFE — Suspicious Features: 0

**Phishing URL:** `http://paypal-secure-login.tk/account/verify?id=12345`
- Risk Score: 99% — Verdict: PHISHING — Flagged: No HTTPS, Suspicious TLD (.tk), 5 suspicious keywords

### Network Scanning
**Critical System:** 8 open ports, 5 HIGH RISK (MySQL, MongoDB, Redis, RDP, SMB)
- Risk Score: 95 — Status: CRITICAL — Immediate remediation required

**Secure System:** 2 open ports, 1 LOW, 1 MEDIUM (SSH, HTTP)
- Risk Score: 5 — Status: MINIMAL — Standard hardening recommended

## 🌐 Live Demo

Try the phishing detector and view a network scanner demo at:
https://crptoangel232.github.io/phishguard/

## 🛠 Tech Stack

- **Python** — Core language
- **Flask** — Web framework
- **scikit-learn** — Machine learning (Random Forest classifier)
- **socket** — Network port scanning
- **concurrent.futures** — Concurrent thread scanning
- **NumPy** — Numerical processing
- **HTML/CSS/JS** — Frontend interface

## 📌 Project Info

- **Builder:** Albert Cho Taylor
- **Domain:** Cybersecurity + AI
- **Contact:** 076988619 · hawakharb@gmail.com

---

⚠️ **Disclaimer:** This tool is for educational and authorized security testing only. Always scan targets you own or have explicit permission to test. The phishing detection model is trained on synthetic data — for production use, train on real datasets like PhishTank or OpenPhish.
