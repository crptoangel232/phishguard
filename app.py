"""
PhishGuard — Security Suite Server

Flask web application combining:
1. Phishing URL Detection (Random Forest ML model, 18 URL features)
2. Network Security Scanner (port scanning, service detection, vulnerability flagging)
"""

import os
import joblib
from flask import Flask, request, jsonify, render_template
from features import extract_features, FEATURE_NAMES
from model import train_model
from scanner import scan_target

app = Flask(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.joblib')


def load_model():
    """Load the trained model, or train a new one if it doesn't exist."""
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    else:
        print("No trained model found. Training new model...")
        model, _ = train_model()
        return model


model = load_model()


@app.route('/')
def index():
    return render_template('index.html')


# ==================== PHISHING DETECTION ====================

@app.route('/api/detect', methods=['POST'])
def detect():
    """Detect if a URL is phishing or legitimate."""
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    feature_values, feature_dict = extract_features(url)
    prediction = model.predict([feature_values])[0]
    probability = model.predict_proba([feature_values])[0]

    phishing_prob = probability[1] if len(probability) > 1 else probability[0]
    risk_score = round(phishing_prob * 100, 1)

    if risk_score >= 75:
        risk_level = 'HIGH'
        risk_color = '#FF3D00'
    elif risk_score >= 40:
        risk_level = 'MEDIUM'
        risk_color = '#FFD600'
    else:
        risk_level = 'LOW'
        risk_color = '#00C853'

    feature_breakdown = []
    for i, name in enumerate(FEATURE_NAMES):
        val = feature_values[i]
        suspicious = False
        note = ''

        if name == 'Has IP Address' and val == 1:
            suspicious = True; note = 'IP address in URL — common in phishing'
        elif name == 'Has @ Symbol' and val == 1:
            suspicious = True; note = '@ symbol can hide the real domain'
        elif name == 'Uses HTTPS' and val == 0:
            suspicious = True; note = 'No HTTPS — unencrypted connection'
        elif name == 'Suspicious TLD' and val == 1:
            suspicious = True; note = 'Top-level domain associated with phishing'
        elif name == 'Suspicious Keywords' and val >= 2:
            suspicious = True; note = f'{val} suspicious keywords detected'
        elif name == 'URL Length' and val > 75:
            suspicious = True; note = f'Unusually long URL ({val} chars)'
        elif name == 'Number of Dots' and val > 5:
            suspicious = True; note = f'Excessive subdomains ({val} dots)'
        elif name == 'Punycode/IDN' and val == 1:
            suspicious = True; note = 'Punycode detected — possible homograph attack'
        elif name == 'Hex Encoding' and val == 1:
            suspicious = True; note = 'Hex-encoded characters in URL'
        elif name == 'Has Port' and val == 1:
            suspicious = True; note = 'Non-standard port in URL'

        feature_breakdown.append({
            'name': name, 'value': val,
            'suspicious': suspicious, 'note': note
        })

    suspicious_count = sum(1 for f in feature_breakdown if f['suspicious'])

    return jsonify({
        'url': url,
        'is_phishing': bool(prediction),
        'risk_score': risk_score,
        'risk_level': risk_level,
        'risk_color': risk_color,
        'suspicious_features': suspicious_count,
        'total_features': len(feature_breakdown),
        'features': feature_breakdown,
        'legitimate_probability': round(probability[0] * 100, 1),
        'phishing_probability': round(phishing_prob * 100, 1)
    })


# ==================== NETWORK SCANNER ====================

@app.route('/api/scan', methods=['POST'])
def network_scan():
    """Scan a target for open ports and vulnerabilities."""
    data = request.get_json()
    target = data.get('target', '').strip()
    custom_ports = data.get('ports', None)

    if not target:
        return jsonify({'error': 'No target provided'}), 400

    # Parse custom ports if provided
    ports = None
    if custom_ports:
        try:
            ports = [int(p.strip()) for p in custom_ports.split(',') if p.strip()]
            if not ports:
                ports = None
        except ValueError:
            return jsonify({'error': 'Invalid port format. Use comma-separated numbers (e.g., 80,443,22)'}), 400

    result = scan_target(target, ports=ports, timeout=1.0)

    if 'error' in result:
        return jsonify(result), 400

    return jsonify(result)


@app.route('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'services': {
            'phishing_detection': model is not None,
            'network_scanner': True
        }
    })


if __name__ == '__main__':
    print("PhishGuard Security Suite running on http://localhost:5000")
    app.run(debug=True, port=5000)
