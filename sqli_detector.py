"""
SQL Injection & XSS Detector — Ethical Hacking Tool

Tests web forms and URL parameters for SQL injection and Cross-Site Scripting
vulnerabilities using safe, non-destructive payloads. Detects error-based SQLi,
blind SQLi indicators, and reflected/stored XSS vectors.
"""

import re
import urllib.parse
from datetime import datetime

# Safe SQL injection test payloads (detection only, no data extraction)
SQLI_PAYLOADS = [
    ("Single quote", "'"),
    ("Double quote", '"'),
    ("Single quote + comment", "'--"),
    ("OR true (numeric)", "1 OR 1=1"),
    ("OR true (string)", "' OR '1'='1"),
    ("OR true + comment", "' OR 1=1--"),
    ("UNION SELECT", "' UNION SELECT NULL--"),
    ("Stacked query", "'; SELECT 1--"),
    ("Boolean false", "' AND '1'='2"),
    ("Time-based (heavy)", "1; WAITFOR DELAY '0:0:0'--"),
    ("Comment variant", "/**/"),
    ("Hex encoding", "0x41"),
    ("Char function", "CHAR(65)"),
    ("Sleep (MySQL)", "' AND SLEEP(0)--"),
    ("LIKE injection", "' OR 'x' LIKE 'x"),
]

# SQL error signatures for detection
SQL_ERROR_SIGNATURES = [
    (r"SQL syntax.*MySQL", "MySQL syntax error"),
    (r"Warning.*mysql_", "MySQL warning"),
    (r"valid MySQL result", "MySQL result error"),
    (r"MySqlException", "MySQL exception"),
    (r"PostgreSQL.*ERROR", "PostgreSQL error"),
    (r"Warning.*pg_", "PostgreSQL warning"),
    (r"valid PostgreSQL result", "PostgreSQL result error"),
    (r"Npgsql\.", "PostgreSQL .NET error"),
    (r"Driver.*SQL-Server", "SQL Server driver error"),
    (r"OLE DB.*SQL Server", "SQL Server OLE DB error"),
    (r"SQL Server.*Driver", "SQL Server driver error"),
    (r"\bORA-[0-9]{4,5}", "Oracle error"),
    (r"Oracle error", "Oracle error"),
    (r"Oracle.*Driver", "Oracle driver error"),
    (r"Warning.*sqlite_", "SQLite warning"),
    (r"SQLite3::query", "SQLite error"),
    (r"SQLite/JDBCDriver", "SQLite JDBC error"),
    (r"Microsoft.*ODBC.*SQL Server", "SQL Server ODBC error"),
    (r"Unclosed quotation mark", "SQL Server unclosed quote"),
    (r"Microsoft OLE DB Provider for SQL Server", "SQL Server OLE DB"),
    (r"Incorrect syntax near", "SQL Server syntax error"),
    (r"Syntax error in string in query expression", "Access syntax error"),
    (r"Data type mismatch in criteria expression", "Access type error"),
    (r"ADODB\.Field", "ADODB error"),
    (r"Microsoft JET Database", "JET database error"),
    (r"You have an error in your SQL syntax", "MySQL syntax error"),
    (r"syntax to use near", "SQL syntax error"),
    (r"malformed numeric literal", "SQLite error"),
    (r"unrecognized token", "SQLite error"),
]

# XSS test payloads
XSS_PAYLOADS = [
    ("Basic script tag", "<script>alert(1)</script>"),
    ("Script with event", "<img src=x onerror=alert(1)>"),
    ("Body onload", "<body onload=alert(1)>"),
    ("SVG onload", "<svg onload=alert(1)>"),
    ("Iframe injection", "<iframe src=javascript:alert(1)>"),
    ("JavaScript URL", "javascript:alert(1)"),
    ("Encoded script", "<scr<script>ipt>alert(1)</script>"),
    ("Event handler", "\" onmouseover=alert(1) \""),
    ("Style expression", "<style>@import('javascript:alert(1)')</style>"),
    ("Data URI", "<object data=javascript:alert(1)>"),
    ("Input attribute", "\"><script>alert(1)</script>"),
    ("Meta refresh", "<meta http-equiv=refresh content=0;url=javascript:alert(1)>"),
    ("Form action hijack", "<form action=javascript:alert(1)><input type=submit>"),
    ("SVG foreignObject", "<svg><foreignObject><body onload=alert(1)>"),
    ("Template injection", "{{constructor.constructor('alert(1)')()}}"),
]

# XSS reflection detection patterns
XSS_REFLECTION_PATTERNS = [
    (r"<script>alert\(1\)</script>", "Unfiltered <script> tag"),
    (r"<img[^>]*onerror", "Unfiltered onerror handler"),
    (r"<body[^>]*onload", "Unfiltered onload handler"),
    (r"<svg[^>]*onload", "Unfiltered SVG onload"),
    (r"<iframe[^>]*src.*javascript:", "Unfiltered iframe javascript"),
    (r"javascript:alert", "Unfiltered javascript: URI"),
    (r"onmouseover=alert", "Unfiltered event handler"),
    (r"<object[^>]*data.*javascript:", "Unfiltered object data"),
    (r"<meta[^>]*refresh.*javascript:", "Unfiltered meta refresh"),
]


def analyze_url_for_sqli(url):
    """Analyze a URL for potential SQL injection points."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    injection_points = []
    for param_name, param_values in params.items():
        for value in param_values:
            injection_points.append({
                'location': 'URL Parameter',
                'parameter': param_name,
                'value': value[:100],
                'risk': 'medium' if value else 'low',
                'note': f'Parameter "{param_name}" is injectable via URL'
            })

    # Check for ID-like parameters
    for param_name in params:
        if any(keyword in param_name.lower() for keyword in ['id', 'uid', 'pid', 'cat', 'page', 'item', 'product', 'user']):
            injection_points.append({
                'location': 'URL Parameter (likely DB query)',
                'parameter': param_name,
                'value': params[param_name][0][:100],
                'risk': 'high',
                'note': f'Parameter "{param_name}" likely maps to a database query'
            })

    return injection_points


def analyze_url_for_xss(url):
    """Analyze a URL for potential XSS vectors."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    xss_points = []
    for param_name, param_values in params.items():
        for value in param_values:
            xss_points.append({
                'location': 'URL Parameter',
                'parameter': param_name,
                'value': value[:100],
                'risk': 'high' if any(c in value for c in '<>"\'') else 'medium',
                'note': f'Parameter "{param_name}" could reflect user input'
            })

    # Check for search query params
    for param_name in params:
        if any(kw in param_name.lower() for kw in ['q', 'query', 'search', 'name', 'msg', 'text', 'comment', 'description']):
            xss_points.append({
                'location': 'URL Parameter (likely reflected)',
                'parameter': param_name,
                'value': params[param_name][0][:100],
                'risk': 'high',
                'note': f'Parameter "{param_name}" likely gets reflected in the page'
            })

    return xss_points


def check_sqli_response(response_body, payload):
    """Check if a response body contains SQL error signatures."""
    findings = []
    for pattern, description in SQL_ERROR_SIGNATURES:
        if re.search(pattern, response_body, re.IGNORECASE):
            findings.append({
                'type': 'error_based_sqli',
                'severity': 'critical',
                'description': description,
                'payload': payload,
                'evidence': re.search(pattern, response_body, re.IGNORECASE).group(0)[:200]
            })

    # Check for boolean-based indicators
    if "true" in response_body.lower() or "1=1" in response_body:
        findings.append({
            'type': 'boolean_based_sqli',
            'severity': 'high',
            'description': 'Boolean-based SQLi indicator detected',
            'payload': payload
        })

    return findings


def check_xss_reflection(response_body, payload):
    """Check if an XSS payload is reflected unfiltered in the response."""
    findings = []
    for pattern, description in XSS_REFLECTION_PATTERNS:
        if re.search(pattern, response_body, re.IGNORECASE):
            findings.append({
                'type': 'reflected_xss',
                'severity': 'critical',
                'description': description,
                'payload': payload,
                'evidence': re.search(pattern, response_body, re.IGNORECASE).group(0)[:200]
            })

    # Check if payload is reflected at all (even if filtered)
    if payload in response_body:
        findings.append({
            'type': 'payload_reflected',
            'severity': 'high',
            'description': 'Payload reflected in response (may be partially filtered)',
            'payload': payload
        })

    return findings


def scan_web_app(url, response_body=None, response_headers=None):
    """
    Analyze a URL and optional response for SQLi and XSS vulnerabilities.
    If response_body is provided, test payloads against it.
    """
    if not url:
        return {'error': 'No URL provided'}

    results = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'sql_injection': {
            'injection_points': analyze_url_for_sqli(url),
            'payloads_tested': len(SQLI_PAYLOADS),
            'vulnerabilities': [],
            'payloads': [{'name': p[0], 'payload': p[1]} for p in SQLI_PAYLOADS]
        },
        'xss': {
            'injection_points': analyze_url_for_xss(url),
            'payloads_tested': len(XSS_PAYLOADS),
            'vulnerabilities': [],
            'payloads': [{'name': p[0], 'payload': p[1]} for p in XSS_PAYLOADS]
        },
        'recommendations': []
    }

    # If response body provided, check for actual vulnerabilities
    if response_body:
        for name, payload in SQLI_PAYLOADS:
            sqli_findings = check_sqli_response(response_body, payload)
            results['sql_injection']['vulnerabilities'].extend(sqli_findings)

        for name, payload in XSS_PAYLOADS:
            xss_findings = check_xss_reflection(response_body, payload)
            results['xss']['vulnerabilities'].extend(xss_findings)

    # Check response headers for security misconfigurations
    if response_headers:
        security_headers = {
            'X-XSS-Protection': 'XSS protection header',
            'X-Content-Type-Options': 'Content type protection',
            'X-Frame-Options': 'Clickjacking protection',
            'Content-Security-Policy': 'Content Security Policy'
        }
        missing_headers = []
        for header, desc in security_headers.items():
            if header not in response_headers:
                missing_headers.append({'header': header, 'description': desc})
                results['recommendations'].append(f'Add {header} header for {desc}')

        results['security_headers'] = {
            'present': [h for h in security_headers if h in (response_headers or {})],
            'missing': missing_headers
        }

    # Generate recommendations
    if results['sql_injection']['injection_points']:
        results['recommendations'].append('Use parameterized queries / prepared statements for all database operations')
        results['recommendations'].append('Implement input validation and sanitization')
        results['recommendations'].append('Use ORM frameworks that automatically escape inputs')

    if results['xss']['injection_points']:
        results['recommendations'].append('Encode all user input before rendering (HTML, JavaScript, CSS encoding)')
        results['recommendations'].append('Implement Content Security Policy (CSP) headers')
        results['recommendations'].append('Use frameworks with automatic output encoding (React, Angular)')

    if results['sql_injection']['vulnerabilities']:
        results['risk_level'] = 'CRITICAL'
        results['recommendations'].insert(0, 'CRITICAL: Active SQL injection vulnerabilities detected — patch immediately')
    elif results['xss']['vulnerabilities']:
        results['risk_level'] = 'CRITICAL'
        results['recommendations'].insert(0, 'CRITICAL: Active XSS vulnerabilities detected — patch immediately')
    elif results['sql_injection']['injection_points']:
        results['risk_level'] = 'HIGH'
    elif results['xss']['injection_points']:
        results['risk_level'] = 'MEDIUM'
    else:
        results['risk_level'] = 'LOW'
        results['recommendations'].append('No obvious injection points detected in URL. Continue monitoring.')

    return results
