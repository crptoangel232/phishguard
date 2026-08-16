"""
PhishGuard — Security Suite Server

10 cybersecurity tools in one Flask application:
1. Phishing URL Detector (ML-based, 18 features)
2. Network Port Scanner (68 ports, service detection)
3. Password Strength Auditor (entropy, crack-time, pattern analysis)
4. SQL Injection & XSS Detector (payload testing, vulnerability scanning)
5. Log Analyzer & Threat Correlator (brute force, impossible travel, attack chains)
6. IOC Scanner (IP, domain, hash, URL reputation checking)
7. Forensic Timeline Builder (kill chain mapping, MITRE ATT&CK)
8. IR Playbook Engine (NIST SP 800-61 incident response procedures)
9. Mini-SIEM Dashboard (log aggregation, alerting, metrics)
10. Alert Correlation Engine (deduplication, incident grouping)
"""

import os
import joblib
from flask import Flask, request, jsonify, render_template
from features import extract_features, FEATURE_NAMES
from model import train_model
from scanner import scan_target
from password_auditor import audit_password
from sqli_detector import scan_web_app
from log_analyzer import analyze_logs
from ioc_scanner import scan_ioc
from forensic_timeline import build_timeline, parse_raw_logs
from ir_playbook import generate_playbook, list_incident_types
from siem_engine import create_siem_instance
from alert_correlation import AlertCorrelationEngine

app = Flask(__name__)
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.joblib')


def load_model():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    else:
        print("Training new model...")
        model, _ = train_model()
        return model


model = load_model()
siem = create_siem_instance()


@app.route('/')
def index():
    return render_template('index.html')


# === 1. PHISHING DETECTION ===
@app.route('/api/detect', methods=['POST'])
def detect():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    feature_values, feature_dict = extract_features(url)
    prediction = model.predict([feature_values])[0]
    probability = model.predict_proba([feature_values])[0]

    phishing_prob = probability[1] if len(probability) > 1 else probability[0]
    risk_score = round(phishing_prob * 100, 1)

    if risk_score >= 75: risk_level, risk_color = 'HIGH', '#FF3D00'
    elif risk_score >= 40: risk_level, risk_color = 'MEDIUM', '#FFD600'
    else: risk_level, risk_color = 'LOW', '#00C853'

    feature_breakdown = []
    for i, name in enumerate(FEATURE_NAMES):
        val = feature_values[i]
        suspicious, note = False, ''
        checks = [
            ('Has IP Address', val == 1, 'IP address in URL — common in phishing'),
            ('Has @ Symbol', val == 1, '@ symbol can hide the real domain'),
            ('Uses HTTPS', val == 0, 'No HTTPS — unencrypted connection'),
            ('Suspicious TLD', val == 1, 'Top-level domain associated with phishing'),
            ('Suspicious Keywords', val >= 2, f'{val} suspicious keywords detected'),
            ('URL Length', val > 75, f'Unusually long URL ({val} chars)'),
            ('Number of Dots', val > 5, f'Excessive subdomains ({val} dots)'),
            ('Punycode/IDN', val == 1, 'Punycode detected — possible homograph attack'),
            ('Hex Encoding', val == 1, 'Hex-encoded characters in URL'),
            ('Has Port', val == 1, 'Non-standard port in URL'),
        ]
        for check_name, condition, check_note in checks:
            if name == check_name and condition:
                suspicious, note = True, check_note
        feature_breakdown.append({'name': name, 'value': val, 'suspicious': suspicious, 'note': note})

    suspicious_count = sum(1 for f in feature_breakdown if f['suspicious'])
    return jsonify({
        'url': url, 'is_phishing': bool(prediction), 'risk_score': risk_score,
        'risk_level': risk_level, 'risk_color': risk_color,
        'suspicious_features': suspicious_count, 'total_features': len(feature_breakdown),
        'features': feature_breakdown,
        'legitimate_probability': round(probability[0] * 100, 1),
        'phishing_probability': round(phishing_prob * 100, 1)
    })


# === 2. NETWORK SCANNER ===
@app.route('/api/scan', methods=['POST'])
def network_scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'error': 'No target provided'}), 400
    result = scan_target(target, timeout=1.0)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


# === 3. PASSWORD AUDITOR ===
@app.route('/api/password-audit', methods=['POST'])
def password_audit():
    data = request.get_json()
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'No password provided'}), 400
    result = audit_password(password)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


# === 4. SQL INJECTION & XSS DETECTOR ===
@app.route('/api/sqli-scan', methods=['POST'])
def sqli_scan():
    data = request.get_json()
    url = data.get('url', '').strip()
    response_body = data.get('response_body')
    response_headers = data.get('response_headers')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    result = scan_web_app(url, response_body, response_headers)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


# === 5. LOG ANALYZER ===
@app.route('/api/analyze-logs', methods=['POST'])
def analyze_logs_api():
    data = request.get_json()
    log_content = data.get('log_content', '')
    log_type = data.get('log_type', 'ssh')
    if not log_content:
        return jsonify({'error': 'No log content provided'}), 400
    result = analyze_logs(log_content, log_type)
    if 'error' in result:
        return jsonify(result), 400

    # Also feed events into SIEM
    from log_analyzer import parse_log_line
    events = []
    for line in log_content.strip().split('\n'):
        parsed = parse_log_line(line, log_type)
        if parsed:
            events.append(parsed)
    if events:
        siem.ingest_events(events)

    return jsonify(result)


# === 6. IOC SCANNER ===
@app.route('/api/ioc-scan', methods=['POST'])
def ioc_scan():
    data = request.get_json()
    indicator = data.get('indicator', '').strip()
    if not indicator:
        return jsonify({'error': 'No indicator provided'}), 400
    result = scan_ioc(indicator)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


# === 7. FORENSIC TIMELINE ===
@app.route('/api/forensic-timeline', methods=['POST'])
def forensic_timeline():
    data = request.get_json()
    log_content = data.get('log_content', '')
    log_type = data.get('log_type', 'ssh')
    if not log_content:
        return jsonify({'error': 'No log content provided'}), 400
    result = parse_raw_logs(log_content, log_type)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


# === 8. IR PLAYBOOK ===
@app.route('/api/ir-playbook', methods=['POST'])
def ir_playbook():
    data = request.get_json()
    incident_type = data.get('incident_type', '')
    if not incident_type:
        return jsonify({'error': 'No incident type provided', 'available': list_incident_types()}), 400
    result = generate_playbook(incident_type)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


@app.route('/api/ir-types')
def ir_types():
    return jsonify({'types': list_incident_types()})


# === 9. SIEM DASHBOARD ===
@app.route('/api/siem-dashboard')
def siem_dashboard():
    return jsonify(siem.get_dashboard())


@app.route('/api/siem-ingest', methods=['POST'])
def siem_ingest():
    data = request.get_json()
    log_content = data.get('log_content', '')
    log_type = data.get('log_type', 'ssh')
    if not log_content:
        return jsonify({'error': 'No log content provided'}), 400
    from log_analyzer import parse_log_line
    events = []
    for line in log_content.strip().split('\n'):
        parsed = parse_log_line(line, log_type)
        if parsed:
            events.append(parsed)
    siem.ingest_events(events)
    return jsonify(siem.get_dashboard())


# === 10. ALERT CORRELATION ===
@app.route('/api/correlate-alerts', methods=['POST'])
def correlate_alerts():
    alerts = siem.alerts
    if not alerts:
        return jsonify({'error': 'No alerts to correlate. Ingest logs first.'}), 400
    engine = AlertCorrelationEngine()
    result = engine.ingest_alerts(alerts)
    return jsonify(result)


# === HEALTH ===
@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'tools': [
            'phishing_detector', 'network_scanner', 'password_auditor',
            'sqli_detector', 'log_analyzer', 'ioc_scanner',
            'forensic_timeline', 'ir_playbook', 'siem_dashboard', 'alert_correlation'
        ]
    })


if __name__ == '__main__':
    print("PhishGuard Security Suite — 10 tools running on http://localhost:5000")
    app.run(debug=True, port=5000)
