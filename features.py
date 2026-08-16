"""
URL Feature Extraction Module

Extracts 18 features from URLs commonly used in phishing detection research.
Based on features from the PhishTank dataset and academic literature on phishing detection.
"""

import re
import ipaddress
from urllib.parse import urlparse, parse_qs
import math


def extract_features(url):
    """
    Extract features from a URL for phishing detection.
    Returns a list of numeric features and a dict of feature names + values for display.
    """
    # Ensure URL has a scheme for proper parsing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    path = parsed.path
    query = parsed.query
    full_url = url

    features = {}
    feature_values = []

    # 1. URL Length (phishing URLs tend to be longer)
    features['url_length'] = len(full_url)
    feature_values.append(len(full_url))

    # 2. Domain Length
    features['domain_length'] = len(domain)
    feature_values.append(len(domain))

    # 3. Has IP Address in URL (phishing often uses IP instead of domain)
    has_ip = 0
    try:
        # Remove port if present
        domain_no_port = domain.split(':')[0]
        ipaddress.ip_address(domain_no_port)
        has_ip = 1
    except ValueError:
        pass
    features['has_ip'] = has_ip
    feature_values.append(has_ip)

    # 4. Has @ Symbol (everything before @ is ignored in URLs)
    has_at = 1 if '@' in full_url else 0
    features['has_at'] = has_at
    feature_values.append(has_at)

    # 5. Uses HTTPS (legitimate sites usually use HTTPS)
    uses_https = 1 if parsed.scheme == 'https' else 0
    features['uses_https'] = uses_https
    feature_values.append(uses_https)

    # 6. Number of Dots in URL (phishing URLs often have many subdomains)
    num_dots = full_url.count('.')
    features['num_dots'] = num_dots
    feature_values.append(num_dots)

    # 7. Number of Dashes in URL
    num_dashes = full_url.count('-')
    features['num_dashes'] = num_dashes
    feature_values.append(num_dashes)

    # 8. Number of Subdomains
    subdomains = domain.split('.')[:-2] if len(domain.split('.')) > 2 else []
    num_subdomains = len(subdomains)
    features['num_subdomains'] = num_subdomains
    feature_values.append(num_subdomains)

    # 9. Has Suspicious TLD
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'country', 'stream', 'download', 'zip', 'review']
    tld = domain.split('.')[-1].lower() if '.' in domain else ''
    has_suspicious_tld = 1 if tld in suspicious_tlds else 0
    features['has_suspicious_tld'] = has_suspicious_tld
    feature_values.append(has_suspicious_tld)

    # 10. Has Port in URL
    has_port = 1 if ':' in domain and not domain.split(':')[-1].isdigit() == False else 0
    if ':' in domain:
        port_part = domain.split(':')[-1]
        has_port = 1 if port_part.isdigit() else 0
    features['has_port'] = has_port
    feature_values.append(has_port)

    # 11. Query Parameters Count
    num_query_params = len(parse_qs(query))
    features['num_query_params'] = num_query_params
    feature_values.append(num_query_params)

    # 12. Path Length
    features['path_length'] = len(path)
    feature_values.append(len(path))

    # 13. Has Double Slash in Path (redirect indicator)
    has_double_slash = 1 if '//' in path else 0
    features['has_double_slash'] = has_double_slash
    feature_values.append(has_double_slash)

    # 14. Has Suspicious Words
    suspicious_words = [
        'login', 'signin', 'verify', 'account', 'password', 'bank', 'secure',
        'update', 'confirm', 'wallet', 'alert', 'suspend', 'activate', 'validate',
        'free', 'gift', 'bonus', 'prize', 'winner', 'selected', 'claim',
        'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
        'netflix', 'instagram', 'whatsapp', 'crypto', 'bitcoin'
    ]
    url_lower = full_url.lower()
    num_suspicious_words = sum(1 for word in suspicious_words if word in url_lower)
    features['num_suspicious_words'] = num_suspicious_words
    feature_values.append(num_suspicious_words)

    # 15. Has Hex Encoding (%XX patterns)
    hex_pattern = re.findall(r'%[0-9a-fA-F]{2}', full_url)
    has_hex_encoding = 1 if len(hex_pattern) > 0 else 0
    features['has_hex_encoding'] = has_hex_encoding
    feature_values.append(has_hex_encoding)

    # 16. Digit-to-Letter Ratio in Domain
    domain_alpha = sum(1 for c in domain if c.isalpha())
    domain_digit = sum(1 for c in domain if c.isdigit())
    if domain_alpha > 0:
        digit_letter_ratio = domain_digit / (domain_alpha + domain_digit)
    else:
        digit_letter_ratio = 0
    features['digit_letter_ratio'] = round(digit_letter_ratio, 3)
    feature_values.append(round(digit_letter_ratio, 3))

    # 17. Has Punycode / IDN (internationalized domain names — phishing homograph attacks)
    has_punycode = 1 if 'xn--' in domain.lower() else 0
    features['has_punycode'] = has_punycode
    feature_values.append(has_punycode)

    # 18. URL Entropy (phishing URLs often have higher entropy — random strings)
    def calculate_entropy(s):
        if not s:
            return 0
        freq = {}
        for char in s:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0
        for count in freq.values():
            p = count / len(s)
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    url_entropy = calculate_entropy(full_url)
    features['url_entropy'] = url_entropy
    feature_values.append(url_entropy)

    return feature_values, features


# Feature names in order
FEATURE_NAMES = [
    'URL Length', 'Domain Length', 'Has IP Address', 'Has @ Symbol',
    'Uses HTTPS', 'Number of Dots', 'Number of Dashes', 'Number of Subdomains',
    'Suspicious TLD', 'Has Port', 'Query Params', 'Path Length',
    'Double Slash Redirect', 'Suspicious Keywords', 'Hex Encoding',
    'Digit Ratio', 'Punycode/IDN', 'URL Entropy'
]
