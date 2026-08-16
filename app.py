"""
PhishGuard — Phishing URL Detection Server

Flask web application that detects phishing URLs using a trained Random Forest model.
Extracts 18 features from each URL and provides a risk score with full feature breakdown.
"""

import os
import joblib
from flask import Flask, request, jsonify, render_template
from features import extract_features, FEATURE_NAMES
from model import train_model

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


@app.route('/api/detect', methods=['POST'])
def detect():
    """Detect if a URL is phishing or legitimate."""
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Extract features
    feature_values, feature_dict = extract_features(url)

    # Predict
    prediction = model.predict([feature_values])[0]
    probability = model.predict_proba([feature_values])[0]

    # Risk score (0-100)
    phishing_prob = probability[1] if len(probability) > 1 else probability[0]
    risk_score = round(phishing_prob * 100, 1)

    # Determine risk level
    if risk_score >= 75:
        risk_level = 'HIGH'
        risk_color = '#FF3D00'
    elif risk_score >= 40:
        risk_level = 'MEDIUM'
        risk_color = '#FFD600'
    else:
        risk_level = 'LOW'
        risk_color = '#00C853'

    # Build feature breakdown for display
    feature_breakdown = []
    for i, name in enumerate(FEATURE_NAMES):
        val = feature_values[i]
        # Determine if this feature is suspicious
        suspicious = False
        note = ''

        if name == 'Has IP Address' and val == 1:
            suspicious = True
            note = 'IP address in URL — common in phishing'
        elif name == 'Has @ Symbol' and val == 1:
            suspicious = True
            note = '@ symbol can hide the real domain'
        elif name == 'Uses HTTPS' and val == 0:
            suspicious = True
            note = 'No HTTPS — unencrypted connection'
        elif name == 'Suspicious TLD' and val == 1:
            suspicious = True
            note = 'Top-level domain associated with phishing'
        elif name == 'Suspicious Keywords' and val >= 2:
            suspicious = True
            note = f'{val} suspicious keywords detected'
        elif name == 'URL Length' and val > 75:
            suspicious = True
            note = f'Unusually long URL ({val} chars)'
        elif name == 'Number of Dots' and val > 5:
            suspicious = True
            note = f'Excessive subdomains ({val} dots)'
        elif name == 'Punycode/IDN' and val == 1:
            suspicious = True
            note = 'Punycode detected — possible homograph attack'
        elif name == 'Hex Encoding' and val == 1:
            suspicious = True
            note = 'Hex-encoded characters in URL'
        elif name == 'Has Port' and val == 1:
            suspicious = True
            note = 'Non-standard port in URL'

        feature_breakdown.append({
            'name': name,
            'value': val,
            'suspicious': suspicious,
            'note': note
        })

    suspicious_count = sum(1 for f in feature_breakdown if f['suspicious'])

    result = {
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
    }

    return jsonify(result)


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'model_loaded': model is not None})


if __name__ == '__main__':
    print("PhishGuard running on http://localhost:5000")
    app.run(debug=True, port=5000)
