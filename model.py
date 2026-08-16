"""
Model Training Module

Trains a Random Forest classifier on synthetic phishing/legitimate URL data.
The synthetic data is generated based on known phishing patterns from academic research.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
from features import extract_features

# Legitimate URL examples (for synthetic data generation)
LEGITIMATE_URLS = [
    'https://www.google.com/search?q=hello',
    'https://www.github.com/user/repo',
    'https://www.python.org/downloads/',
    'https://www.wikipedia.org/wiki/Phishing',
    'https://www.amazon.com/product/12345',
    'https://www.youtube.com/watch?v=abcdef',
    'https://www.linkedin.com/in/user',
    'https://www.stackoverflow.com/questions/12345',
    'https://www.reddit.com/r/programming',
    'https://www.microsoft.com/en-us/windows',
    'https://www.apple.com/iphone',
    'https://www.cloudflare.com/dns',
    'https://docs.python.org/3/library',
    'https://www.figma.com/file/123',
    'https://www.notion.so/page/123',
    'https://www.stripe.com/docs/api',
    'https://www.vercel.com/dashboard',
    'https://www.npmjs.com/package/react',
    'https://www.medium.com/article/title',
    'https://www.bbc.com/news/world',
    'https://www.unsplash.com/photos/123',
    'https://www.spotify.com/playlist/123',
    'https://www.netflix.com/title/12345',
    'https://www.mozilla.org/firefox',
    'https://www.docker.com/hub',
    'https://www.atlassian.com/jira',
    'https://www.slack.com/workspace',
    'https://www.dropbox.com/home/files',
    'https://www.zoom.us/meeting/123',
    'https://www.coursera.org/course/data',
]

# Phishing URL patterns (based on real phishing characteristics)
PHISHING_PATTERNS = [
    'http://192.168.1.1/login.php?account=verify',
    'http://paypal-secure-login.tk/account/verify?id=12345',
    'http://amazon-update.ml/signin?email=alert@xyz',
    'http://192.168.0.50:8080/bank/login.html',
    'https://secure-paypal-verify.gq/login.html?token=abc',
    'http://appleid-apple-login.xyz/verify/account',
    'http://netflix-update-billing.cf/?user=confirm&pw=true',
    'http://192.168.10.5/google/login.php',
    'http://facebook-secure-login.top/account/recover?email=true',
    'http://microsoft-verify-account.click/office365/login',
    'http://bitbank-crypto-wallet.xyz/login?seed=abc123',
    'http://192.168.55.10/amazon/signin.html',
    'http://whatsapp-update-msg.gq/activate?phone=true',
    'http://instagram-verify-account.stream/login/recover',
    'http://10.0.0.5/paypal/cgi-bin/webscr?cmd=_login',
    'http://free-gift-card-winner.download/claim?prize=iphone',
    'http://google-account-verify.ml/alert/suspended?action=verify',
    'http://coinbase-wallet-secure.xyz/login?seed=verify',
    'http://192.168.100.1:443/bankofamerica/login.html',
    'http://amazon-prize-winner.review/claim?selected=true',
    'http://appleid-secure-login.tk/account/verify?id=lock',
    'http://paypal-update-suspend.gq/cgi-bin/login?account=limited',
    'http://bit.ly/2xYz/login/secure/bank/verify?account=true',
    'http://192.168.2.1/netflix/payment/update?card=true',
    'http://free-bitcoin-bonus.xyz/claim?wallet=verify&bonus=0.5btc',
    'http://microsoft365-update.click/login?email=confirm',
    'http://secure-bank-login-verify.top/account/suspended?action=unlock',
    'http://10.10.10.1/amazon/prime?gift=winner&claim=now',
    'http://facebook-recover-account.stream/recover?login=true',
    'http://gmail-alert-suspend.ml/signin?email=verify&password=confirm',
]


def generate_training_data():
    """Generate training data from legitimate and phishing URLs."""
    X = []
    y = []

    # Process legitimate URLs (label = 0)
    for url in LEGITIMATE_URLS:
        features, _ = extract_features(url)
        X.append(features)
        y.append(0)

    # Process phishing URLs (label = 1)
    for url in PHISHING_PATTERNS:
        features, _ = extract_features(url)
        X.append(features)
        y.append(1)

    # Add some augmented variations
    # Legitimate variations
    for url in LEGITIMATE_URLS[:10]:
        features, _ = extract_features(url + '?ref=homepage&utm=organic')
        X.append(features)
        y.append(0)

    # Phishing variations
    for url in PHISHING_PATTERNS[:10]:
        features, _ = extract_features(url + '&session=' + 'x' * 15)
        X.append(features)
        y.append(1)

    return np.array(X), np.array(y)


def train_model():
    """Train the Random Forest model and save it."""
    print("Generating training data...")
    X, y = generate_training_data()
    print(f"Training data: {len(X)} samples ({sum(y)} phishing, {len(y)-sum(y)} legitimate)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )

    print("Training Random Forest classifier...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    print(f"\nModel Accuracy: {accuracy:.2%}")
    print(f"\nClassification Report:\n{classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing'])}")

    # Feature importance
    feature_names = [
        'URL Length', 'Domain Length', 'Has IP', 'Has @', 'HTTPS',
        'Num Dots', 'Num Dashes', 'Subdomains', 'Suspicious TLD', 'Has Port',
        'Query Params', 'Path Length', 'Double Slash', 'Suspicious Keywords',
        'Hex Encoding', 'Digit Ratio', 'Punycode', 'Entropy'
    ]

    importances = model.feature_importances_
    print("\nFeature Importances:")
    for name, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1]):
        print(f"  {name}: {imp:.4f}")

    model_path = os.path.join(os.path.dirname(__file__), 'phishing_model.joblib')
    joblib.dump(model, model_path)
    print(f"\nModel saved to: {model_path}")

    return model, accuracy


if __name__ == '__main__':
    train_model()
