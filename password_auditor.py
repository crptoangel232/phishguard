"""
Password Strength Auditor — Ethical Hacking Tool

Analyzes password strength, estimates crack times, checks against common patterns,
and generates security recommendations. Simulates hashcat/john-style attacks
without actually cracking — uses entropy and pattern analysis.
"""

import re
import math
import time
from datetime import datetime

# Common passwords (subset of rockyou-style wordlist)
COMMON_PASSWORDS = {
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567',
    'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
    'ashley', 'michael', 'shadow', '123123', '654321', 'superman', 'qazwsx',
    'michael', 'football', 'password1', 'password123', 'welcome', 'hello',
    'charlie', 'donald', 'login', 'starwars', '121212', 'flower', 'freedom',
    'princess', 'passw0rd', 'charlie', 'aaaaaa', '111111', '666666', '000000',
    'qwerty123', '1q2w3e4r', 'admin', 'root', 'toor', 'pass', 'test', 'guest',
    'user', 'admin123', 'welcome1', 'welcome123', 'changeme', 'default'
}

# Keyboard patterns
KEYBOARD_ROWS = [
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
    '1234567890', '0987654321',
    'qwerty', 'qweasdzxc', 'qazwsx',
]

# Common substitutions
LEET_SUBS = {
    '@': 'a', '4': 'a', '$': 's', '5': 's', '0': 'o',
    '1': 'i', '3': 'e', '7': 't', '!': 'i', '|': 'i',
}


def deleet(password):
    """Convert leet-speak back to normal letters."""
    result = password.lower()
    for char, replacement in LEET_SUBS.items():
        result = result.replace(char, replacement)
    return result


def calculate_entropy(password):
    """Calculate Shannon entropy of the password."""
    if not password:
        return 0
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'[0-9]', password): charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset_size += 32
    if charset_size == 0: charset_size = 1
    return len(password) * math.log2(charset_size)


def detect_patterns(password):
    """Detect common patterns in the password."""
    patterns = []
    pw_lower = password.lower()

    # Check common passwords
    if pw_lower in COMMON_PASSWORDS:
        patterns.append({'type': 'common', 'severity': 'critical',
                         'desc': f'"{password}" is in the top 1000 most common passwords'})
    if deleet(pw_lower) in COMMON_PASSWORDS:
        patterns.append({'type': 'common_leet', 'severity': 'critical',
                         'desc': f'After leet-speak decoding, "{deleet(pw_lower)}" is a common password'})

    # Sequential characters
    if re.search(r'(abc|bcd|cde|def|123|234|345|456|567|678|789|890|cba|987|876|765|654|543|432|321|210)', pw_lower):
        patterns.append({'type': 'sequential', 'severity': 'high',
                         'desc': 'Contains sequential characters (abc, 123, etc.)'})

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        match = re.search(r'(.)\1{2,}', password)
        patterns.append({'type': 'repeated', 'severity': 'high',
                         'desc': f'Repeated character "{match.group(1)}" appears {len(match.group(0))} times'})

    # Keyboard patterns
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            substr = row[i:i+4]
            if substr in pw_lower:
                patterns.append({'type': 'keyboard', 'severity': 'high',
                                 'desc': f'Keyboard pattern "{substr}" detected'})

    # All same type
    if password.isdigit():
        patterns.append({'type': 'digits_only', 'severity': 'high',
                         'desc': 'Password contains only digits'})
    if password.isalpha():
        patterns.append({'type': 'alpha_only', 'severity': 'medium',
                         'desc': 'Password contains only letters'})

    # Date patterns
    if re.search(r'(19|20)\d{2}', password):
        patterns.append({'type': 'year', 'severity': 'medium',
                         'desc': 'Contains a year (likely a birth year)'})

    # Common words
    common_words = ['love', 'admin', 'pass', 'user', 'test', 'work', 'home', 'name', 'king', 'queen']
    for word in common_words:
        if word in pw_lower:
            patterns.append({'type': 'common_word', 'severity': 'medium',
                             'desc': f'Contains common word "{word}"'})

    # Short password
    if len(password) < 8:
        patterns.append({'type': 'short', 'severity': 'high',
                         'desc': f'Password is only {len(password)} characters (minimum 8 recommended)'})
    elif len(password) < 12:
        patterns.append({'type': 'shortish', 'severity': 'low',
                         'desc': f'Password is {len(password)} characters (12+ recommended)'})

    return patterns


def estimate_crack_time(entropy):
    """
    Estimate crack time based on entropy.
    Assumes modern GPU: 10 billion guesses/sec (hashcat with RTX 4090).
    """
    if entropy <= 0:
        return {'seconds': 0, 'human': 'Instant'}

    guesses = 2 ** entropy
    guesses_per_second = 10_000_000_000  # 10 billion/sec (GPU)

    seconds = guesses / guesses_per_second

    # Different attack scenarios
    scenarios = {
        'online_throttled': seconds * 100,   # 100 attempts/sec (rate-limited)
        'online_unthrottled': seconds * 10000, # 10k attempts/sec (no rate limit)
        'offline_slow_hash': seconds,         # 10B/sec (bcrypt/scrypt would be slower)
        'offline_fast_hash': seconds / 100,   # MD5/SHA1 - even faster
    }

    def human_time(s):
        if s < 1: return 'Instant'
        if s < 60: return f'{s:.0f} seconds'
        if s < 3600: return f'{s/60:.0f} minutes'
        if s < 86400: return f'{s/3600:.1f} hours'
        if s < 2592000: return f'{s/86400:.1f} days'
        if s < 31536000: return f'{s/2592000:.0f} months'
        if s < 31536000 * 1000: return f'{s/31536000:.0f} years'
        if s < 31536000 * 1e9: return f'{s/31536000/1e6:.0f} million years'
        return 'Centuries'

    return {
        'seconds': seconds,
        'human': human_time(seconds),
        'scenarios': {
            'Online (rate-limited)': human_time(scenarios['online_throttled']),
            'Online (no rate limit)': human_time(scenarios['online_unthrottled']),
            'Offline (GPU, fast hash)': human_time(scenarios['offline_fast_hash']),
            'Offline (GPU, slow hash)': human_time(scenarios['offline_slow_hash']),
        }
    }


def audit_password(password):
    """Run a complete password audit."""
    if not password:
        return {'error': 'No password provided'}

    entropy = calculate_entropy(password)
    patterns = detect_patterns(password)
    crack_time = estimate_crack_time(entropy)

    # Score calculation (0-100, higher is better)
    score = 0
    score += min(len(password) * 5, 40)  # Length up to 40 points
    score += min(entropy * 3, 30)       # Entropy up to 30 points
    if re.search(r'[a-z]', password): score += 5
    if re.search(r'[A-Z]', password): score += 5
    if re.search(r'[0-9]', password): score += 5
    if re.search(r'[^a-zA-Z0-9]', password): score += 5
    if len(password) >= 12: score += 10

    # Penalties
    for p in patterns:
        if p['severity'] == 'critical': score -= 40
        elif p['severity'] == 'high': score -= 15
        elif p['severity'] == 'medium': score -= 8
        elif p['severity'] == 'low': score -= 3

    score = max(0, min(100, score))

    # Strength rating
    if score >= 80: rating = 'Very Strong'
    elif score >= 65: rating = 'Strong'
    elif score >= 50: rating = 'Moderate'
    elif score >= 30: rating = 'Weak'
    else: rating = 'Very Weak'

    # Recommendations
    recommendations = []
    if len(password) < 12:
        recommendations.append('Use at least 12 characters')
    if not re.search(r'[A-Z]', password):
        recommendations.append('Add uppercase letters')
    if not re.search(r'[0-9]', password):
        recommendations.append('Add numbers')
    if not re.search(r'[^a-zA-Z0-9]', password):
        recommendations.append('Add special characters (!@#$%^&*)')
    if any(p['type'] == 'common' or p['type'] == 'common_leet' for p in patterns):
        recommendations.append('This password is in common wordlists — change it immediately')
    if any(p['type'] == 'sequential' for p in patterns):
        recommendations.append('Avoid sequential characters (abc, 123)')
    if any(p['type'] == 'keyboard' for p in patterns):
        recommendations.append('Avoid keyboard patterns (qwerty, asdf)')
    if any(p['type'] == 'repeated' for p in patterns):
        recommendations.append('Avoid repeated characters (aaa, 111)')
    if not recommendations:
        recommendations.append('Password meets basic strength criteria. Consider using a password manager for unique passwords per service.')

    return {
        'password_length': len(password),
        'entropy_bits': round(entropy, 2),
        'strength_score': score,
        'strength_rating': rating,
        'patterns': patterns,
        'crack_time': crack_time,
        'recommendations': recommendations,
        'has_uppercase': bool(re.search(r'[A-Z]', password)),
        'has_lowercase': bool(re.search(r'[a-z]', password)),
        'has_digits': bool(re.search(r'[0-9]', password)),
        'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
        'timestamp': datetime.now().isoformat()
    }
