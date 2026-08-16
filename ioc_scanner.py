"""
IOC (Indicator of Compromise) Scanner — SOC Analysis Tool

Checks file hashes, IP addresses, domains, and URLs against known threat
intelligence patterns. Detects malicious indicators, checks reputation scores,
and correlates IOCs into threat categories.
"""

import re
import hashlib
import ipaddress
from datetime import datetime


# Known malicious IP ranges (simplified threat intel)
MALICIOUS_IP_RANGES = [
    # Tor exit nodes (common for malicious traffic)
    ('100.64.0.0/10', 'Tor/Proxy network'),
    ('185.220.101.0/24', 'Known Tor exit node'),
    ('171.25.193.0/24', 'Known Tor exit node'),
    ('89.248.0.0/16', 'Known scanner/botnet C2'),
    ('194.165.16.0/24', 'Known scanner'),
    ('45.155.205.0/24', 'Known malicious scanner'),
    ('193.169.4.0/24', 'Known botnet'),
    ('5.188.206.0/24', 'Known C2 server range'),
    ('141.98.10.0/24', 'Known brute-force source'),
    ('51.91.0.0/16', 'Known scanner network'),
]

# Suspicious domains (patterns)
SUSPICIOUS_DOMAIN_PATTERNS = [
    (r'\.tk$', 'Freenom .tk domain — frequently used for phishing'),
    (r'\.ml$', 'Freenom .ml domain — frequently used for phishing'),
    (r'\.ga$', 'Freenom .ga domain — frequently used for phishing'),
    (r'\.cf$', 'Freenom .cf domain — frequently used for phishing'),
    (r'\.gq$', 'Freenom .gq domain — frequently used for phishing'),
    (r'\.xyz$', '.xyz domain — often used for malicious infrastructure'),
    (r'\.top$', '.top domain — often associated with spam/malware'),
    (r'\.click$', '.click domain — often used for phishing redirects'),
    (r'\.zip$', '.zip domain — can be used for file extension confusion'),
    (r' paypal.*\.', 'Typosquatted PayPal domain'),
    (r' amaz[0o]n.*\.', 'Typosquatted Amazon domain'),
    (r' g[0o]ogle.*\.', 'Typosquatted Google domain'),
    (r' faceb[0o]ok.*\.', 'Typosquatted Facebook domain'),
    (r' netfl[1i]x.*\.', 'Typosquatted Netflix domain'),
    (r' apple.*\.', 'Typosquatted Apple domain'),
    (r' microsoft.*\.', 'Typosquatted Microsoft domain'),
    (r'-\d+\.', 'Domain with numeric suffix — common in malware C2'),
    (r'c2c\b', 'C2 keyword in domain'),
    (r'botnet\b', 'Botnet keyword in domain'),
]

# Known malicious file hash patterns (simplified)
KNOWN_MALWARE_HASHES = {
    '44d88612fea8a8f37de989016ae6c094': ('EICAR Test File', 'Test virus — used for antivirus testing'),
    'eicar': ('EICAR', 'Standard antivirus test string'),
    '3395856ce81f2b7382dee72602f79805': ('Win32/Emotet', 'Banking trojan — credential theft'),
    'a1f2b3c4d5e6f7a8b9c0d1e2f3a4b5c6': ('Win32/TrickBot', 'Modular trojan — information stealer'),
    'b2a3c4d5e6f7a8b9c0d1e2f3a4b5c6d7': ('Win32/Ryuk', 'Ransomware — file encryption'),
    'c3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8': ('Win32/CobaltStrike', 'Penetration testing tool / threat actor'),
    'd4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9': ('Win32/Mimikatz', 'Credential dumping tool'),
}

# Threat categories
THREAT_CATEGORIES = {
    'phishing': ['phish', 'fraud', 'scam', 'social', 'credential'],
    'malware': ['trojan', 'virus', 'worm', 'ransomware', 'backdoor', 'bot'],
    'c2': ['c2', 'command', 'control', 'beacon', 'callback'],
    'scanner': ['scanner', 'recon', 'enumeration', 'crawler'],
    'cryptominer': ['miner', 'cryptonight', 'xmrig', 'monero'],
    'exploit': ['exploit', 'cve', 'vulnerability', 'zero-day'],
}


def check_ip(ip_str):
    """Check an IP address against threat intelligence."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return {'error': f'Invalid IP address: {ip_str}'}

    results = {
        'indicator': ip_str,
        'indicator_type': 'ipv4' if ip.version == 4 else 'ipv6',
        'is_malicious': False,
        'threats': [],
        'reputation': 'clean',
        'recommendations': []
    }

    # Check against malicious ranges
    for cidr, description in MALICIOUS_IP_RANGES:
        try:
            if ip in ipaddress.ip_network(cidr):
                results['is_malicious'] = True
                results['threats'].append({
                    'type': 'known_malicious_network',
                    'severity': 'high',
                    'description': description,
                    'network': cidr
                })
        except:
            pass

    # Private/reserved IPs
    if ip.is_private:
        results['threats'].append({
            'type': 'private_address',
            'severity': 'info',
            'description': 'Private/internal IP address'
        })
        results['reputation'] = 'internal'
    elif ip.is_loopback:
        results['reputation'] = 'localhost'
    elif ip.is_multicast:
        results['threats'].append({
            'type': 'multicast',
            'severity': 'info',
            'description': 'Multicast address'
        })

    if results['is_malicious']:
        results['reputation'] = 'malicious'
        results['recommendations'].append('Block this IP at the firewall immediately')
        results['recommendations'].append('Add to deny list in IPS/IDS')
        results['recommendations'].append('Check for existing connections from this IP')
    else:
        results['recommendations'].append('No known threats for this IP. Monitor for suspicious activity.')

    return results


def check_domain(domain):
    """Check a domain against threat intelligence."""
    domain = domain.lower().strip()
    if not domain:
        return {'error': 'No domain provided'}

    # Remove protocol if present
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]  # Remove path

    results = {
        'indicator': domain,
        'indicator_type': 'domain',
        'is_malicious': False,
        'threats': [],
        'reputation': 'clean',
        'recommendations': []
    }

    # Check suspicious patterns
    for pattern, description in SUSPICIOUS_DOMAIN_PATTERNS:
        if re.search(pattern, domain, re.IGNORECASE):
            results['is_malicious'] = True
            results['threats'].append({
                'type': 'suspicious_domain_pattern',
                'severity': 'medium',
                'description': description
            })

    # Check for typosquatting (common brand domains)
    legit_domains = ['google.com', 'amazon.com', 'facebook.com', 'apple.com', 'microsoft.com',
                     'netflix.com', 'paypal.com', 'twitter.com', 'instagram.com', 'linkedin.com',
                     'github.com', 'dropbox.com', 'whatsapp.com', 'youtube.com']

    domain_base = domain.split('.')[-2] if len(domain.split('.')) >= 2 else domain
    for legit in legit_domains:
        legit_base = legit.split('.')[0]
        # Check for character substitutions
        if domain_base != legit_base and len(domain_base) == len(legit_base):
            diff = sum(1 for a, b in zip(domain_base, legit_base) if a != b)
            if diff <= 2:
                results['is_malicious'] = True
                results['threats'].append({
                    'type': 'typosquatting',
                    'severity': 'high',
                    'description': f'Possible typosquatting of "{legit}" (characters differ: {diff})'
                })

    # Check for IDN/homograph
    if 'xn--' in domain:
        results['is_malicious'] = True
        results['threats'].append({
            'type': 'idn_homograph',
            'severity': 'high',
            'description': 'Punycode/IDN domain — possible homograph attack'
        })

    # Check domain length (unusually long)
    if len(domain) > 30:
        results['threats'].append({
            'type': 'long_domain',
            'severity': 'low',
            'description': f'Unusually long domain ({len(domain)} chars)'
        })

    if results['is_malicious']:
        results['reputation'] = 'suspicious'
        results['recommendations'].append('Block this domain in DNS/proxy filters')
        results['recommendations'].append('Check if any internal systems have communicated with this domain')
        results['recommendations'].append('Add to threat blocklist')
    else:
        results['recommendations'].append('No known threats for this domain.')

    return results


def check_hash(hash_str):
    """Check a file hash against known malware signatures."""
    hash_str = hash_str.lower().strip()
    if not hash_str:
        return {'error': 'No hash provided'}

    # Determine hash type
    hash_type = None
    if len(hash_str) == 32:
        hash_type = 'md5'
    elif len(hash_str) == 40:
        hash_type = 'sha1'
    elif len(hash_str) == 64:
        hash_type = 'sha256'
    else:
        return {'error': f'Unrecognized hash format (length {len(hash_str)}). Expected MD5 (32), SHA1 (40), or SHA256 (64).'}

    results = {
        'indicator': hash_str,
        'indicator_type': f'file_hash_{hash_type}',
        'is_malicious': False,
        'threats': [],
        'reputation': 'unknown',
        'recommendations': []
    }

    # Check against known malware hashes
    if hash_str in KNOWN_MALWARE_HASHES:
        malware_name, description = KNOWN_MALWARE_HASHES[hash_str]
        results['is_malicious'] = True
        results['threats'].append({
            'type': 'known_malware',
            'severity': 'critical',
            'malware_name': malware_name,
            'description': description
        })
        results['reputation'] = 'malicious'
        results['recommendations'].append(f'CRITICAL: File matches {malware_name} — quarantine immediately')
        results['recommendations'].append('Isolate the system where this file was found')
        results['recommendations'].append('Check for lateral movement from this system')
        results['recommendations'].append('Begin incident response procedures')
    else:
        results['reputation'] = 'unknown'
        results['recommendations'].append('Hash not found in local database. Submit to VirusTotal for multi-engine scan.')
        results['recommendations'].append('If this is a file in your environment, sandbox it and analyze behavior.')

    return results


def check_url_ioc(url):
    """Check a URL for IOC indicators."""
    if not url:
        return {'error': 'No URL provided'}

    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    # Extract domain
    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.hostname or ''

    results = {
        'indicator': url,
        'indicator_type': 'url',
        'is_malicious': False,
        'threats': [],
        'reputation': 'clean',
        'recommendations': []
    }

    # Check domain portion
    domain_check = check_domain(domain)
    if domain_check.get('is_malicious'):
        results['is_malicious'] = True
        for threat in domain_check.get('threats', []):
            results['threats'].append(threat)

    # Check for suspicious URL patterns
    if not parsed.scheme == 'https':
        results['threats'].append({
            'type': 'no_https',
            'severity': 'medium',
            'description': 'URL uses HTTP, not HTTPS — unencrypted connection'
        })

    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        results['is_malicious'] = True
        results['threats'].append({
            'type': 'ip_in_url',
            'severity': 'high',
            'description': 'URL contains IP address instead of domain name'
        })

    suspicious_keywords = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'password', 'bank']
    url_lower = url.lower()
    found_kw = [kw for kw in suspicious_keywords if kw in url_lower]
    if len(found_kw) >= 2:
        results['threats'].append({
            'type': 'suspicious_keywords',
            'severity': 'medium',
            'description': f'Contains {len(found_kw)} suspicious keywords: {", ".join(found_kw)}'
        })

    if results['is_malicious']:
        results['reputation'] = 'malicious'
        results['recommendations'].append('Block this URL in web proxy/URL filter')
        results['recommendations'].append('Check proxy/firewall logs for any access to this URL')
    else:
        results['recommendations'].append('No immediate threats detected. Monitor for changes.')

    return results


def scan_ioc(indicator):
    """Auto-detect indicator type and scan."""
    indicator = indicator.strip()

    # Detect type
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', indicator):
        return {'indicator': indicator, 'type': 'IP Address', 'result': check_ip(indicator)}
    elif re.match(r'^[a-f0-9]{32}$', indicator, re.I) or re.match(r'^[a-f0-9]{40}$', indicator, re.I) or re.match(r'^[a-f0-9]{64}$', indicator, re.I):
        return {'indicator': indicator, 'type': 'File Hash', 'result': check_hash(indicator)}
    elif '/' in indicator or indicator.startswith('http'):
        return {'indicator': indicator, 'type': 'URL', 'result': check_url_ioc(indicator)}
    elif '.' in indicator and ' ' not in indicator:
        return {'indicator': indicator, 'type': 'Domain', 'result': check_domain(indicator)}
    else:
        return {'error': f'Unable to determine indicator type for: {indicator}'}
