"""
Log Analyzer & Threat Correlator — SOC Analysis Tool

Parses authentication logs (SSH, Apache, Windows Event), detects brute-force
attacks, failed login clusters, impossible travel, privilege escalation,
and correlates events into attack chains.
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import unquote


# Log format patterns
LOG_PATTERNS = {
    'ssh': {
        'regex': r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[(\d+)\]:\s+(.*)',
        'failed_login': r'Failed password for (?:invalid user )?(\S+) from (\S+) port \d+',
        'accepted_login': r'Accepted password for (\S+) from (\S+) port \d+',
        'invalid_user': r'Invalid user (\S+) from (\S+)',
        'disconnected': r'Disconnected from (\S+) port \d+',
    },
    'apache': {
        'regex': r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)',
        'error_404': r'404',
        'error_403': r'403',
        'error_500': r'500',
    },
    'windows': {
        'regex': r'(\d{4}-\d{2}-\d{2}[\dT\s:]+)\s+(\d+)\s+(\w+)\s+(.*)',
        'failed_login_4625': r'EventID.*4625|Logon Failure',
        'success_login_4624': r'EventID.*4624|Logon Success',
        'account_created': r'EventID.*4720|Account Created',
        'account_locked': r'EventID.*4740|Account Locked',
        'privilege_escalation': r'EventID.*4672|Special Privileges',
    }
}


def parse_log_line(line, log_type='ssh'):
    """Parse a single log line based on log type."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    patterns = LOG_PATTERNS.get(log_type, LOG_PATTERNS['ssh'])
    match = re.match(patterns['regex'], line)
    if not match:
        return None

    parsed = {'raw': line, 'type': log_type}

    if log_type == 'ssh':
        parsed['timestamp_str'] = match.group(1)
        parsed['host'] = match.group(2)
        parsed['pid'] = match.group(3)
        message = match.group(4)
        parsed['message'] = message

        # Detect event type
        for event_type, pattern in [
            ('failed_login', patterns.get('failed_login', '')),
            ('accepted_login', patterns.get('accepted_login', '')),
            ('invalid_user', patterns.get('invalid_user', '')),
            ('disconnected', patterns.get('disconnected', ''))
        ]:
            if pattern:
                m = re.search(pattern, message)
                if m:
                    parsed['event'] = event_type
                    if event_type in ('failed_login', 'accepted_login', 'invalid_user'):
                        parsed['username'] = m.group(1)
                        parsed['source_ip'] = m.group(2)
                    elif event_type == 'invalid_user':
                        parsed['username'] = m.group(1)
                        parsed['source_ip'] = m.group(2)
                    return parsed

        parsed['event'] = 'other'
        return parsed

    elif log_type == 'apache':
        parsed['source_ip'] = match.group(1)
        parsed['timestamp_str'] = match.group(2)
        parsed['method'] = match.group(3)
        parsed['path'] = match.group(4)
        parsed['protocol'] = match.group(5)
        parsed['status'] = int(match.group(6))
        parsed['size'] = int(match.group(7)) if match.group(7) != '-' else 0
        parsed['event'] = 'http_request'
        return parsed

    elif log_type == 'windows':
        parsed['timestamp_str'] = match.group(1)
        parsed['event_id'] = match.group(2)
        parsed['source'] = match.group(3)
        parsed['message'] = match.group(4)

        for event_type, pattern in [
            ('failed_login', patterns.get('failed_login_4625', '')),
            ('success_login', patterns.get('success_login_4624', '')),
            ('account_created', patterns.get('account_created', '')),
            ('account_locked', patterns.get('account_locked', '')),
            ('privilege_escalation', patterns.get('privilege_escalation', ''))
        ]:
            if pattern and re.search(pattern, line):
                parsed['event'] = event_type
                return parsed

        parsed['event'] = 'other'
        return parsed

    return parsed


def detect_brute_force(events, threshold=5, window_minutes=10):
    """Detect brute-force attacks: multiple failed logins from same IP in a time window."""
    # Group failed logins by source IP
    failed_by_ip = defaultdict(list)
    for event in events:
        if event.get('event') == 'failed_login':
            ip = event.get('source_ip', 'unknown')
            failed_by_ip[ip].append(event)

    brute_force_attacks = []
    for ip, attempts in failed_by_ip.items():
        if len(attempts) >= threshold:
            # Check if attempts are within the time window
            brute_force_attacks.append({
                'type': 'brute_force',
                'severity': 'high',
                'source_ip': ip,
                'attempt_count': len(attempts),
                'threshold': threshold,
                'window_minutes': window_minutes,
                'targeted_users': list(set(a.get('username', '?') for a in attempts)),
                'first_attempt': attempts[0].get('timestamp_str', '?'),
                'last_attempt': attempts[-1].get('timestamp_str', '?'),
                'description': f'Brute-force attack from {ip}: {len(attempts)} failed login attempts'
            })

    return brute_force_attacks


def detect_impossible_travel(events, max_distance_km_per_hour=900):
    """Detect impossible travel: logins from different locations too quickly."""
    # This is a simplified version using IP differences as location proxy
    successful_logins = [e for e in events if e.get('event') == 'accepted_login' or e.get('event') == 'success_login']

    if len(successful_logins) < 2:
        return []

    travel_alerts = []
    # Group by username
    by_user = defaultdict(list)
    for login in successful_logins:
        user = login.get('username', login.get('source_ip', '?'))
        by_user[user].append(login)

    for user, logins in by_user.items():
        if len(logins) < 2:
            continue
        for i in range(1, len(logins)):
            prev = logins[i-1]
            curr = logins[i]
            if prev.get('source_ip') != curr.get('source_ip'):
                travel_alerts.append({
                    'type': 'impossible_travel',
                    'severity': 'high',
                    'username': user,
                    'prev_ip': prev.get('source_ip', '?'),
                    'curr_ip': curr.get('source_ip', '?'),
                    'description': f'User "{user}" logged in from {prev.get("source_ip", "?")} then {curr.get("source_ip", "?")} — verify legitimacy'
                })

    return travel_alerts


def detect_privilege_escalation(events):
    """Detect potential privilege escalation."""
    alerts = []
    for event in events:
        if event.get('event') == 'privilege_escalation':
            alerts.append({
                'type': 'privilege_escalation',
                'severity': 'critical',
                'description': f'Special privileges assigned: {event.get("message", "")[:100]}',
                'raw': event.get('raw', '')
            })
    return alerts


def detect_suspicious_http_activity(events):
    """Detect suspicious HTTP patterns in Apache logs."""
    alerts = []

    # High volume of 404s (directory enumeration)
    by_ip = defaultdict(list)
    for event in events:
        if event.get('event') == 'http_request' and event.get('status') == 404:
            by_ip[event.get('source_ip', '?')].append(event)

    for ip, requests in by_ip.items():
        if len(requests) > 20:
            alerts.append({
                'type': 'directory_enumeration',
                'severity': 'medium',
                'source_ip': ip,
                'count': len(requests),
                'description': f'Directory enumeration from {ip}: {len(requests)} 404 responses'
            })

    # SQL injection attempts in URLs
    sqli_patterns = [r'union\s+select', r'\'\s*or\s*1=1', r'--', r';.*select', r'information_schema', r'sleep\(']
    for event in events:
        if event.get('event') == 'http_request':
            path = event.get('path', '')
            for pattern in sqli_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    alerts.append({
                        'type': 'sqli_attempt',
                        'severity': 'high',
                        'source_ip': event.get('source_ip', '?'),
                        'path': path[:200],
                        'description': f'SQL injection attempt from {event.get("source_ip", "?")} on path: {path[:100]}'
                    })
                    break

    # XSS attempts in URLs
    xss_patterns = [r'<script', r'onerror=', r'onload=', r'javascript:', r'alert\(']
    for event in events:
        if event.get('event') == 'http_request':
            path = event.get('path', '')
            for pattern in xss_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    alerts.append({
                        'type': 'xss_attempt',
                        'severity': 'high',
                        'source_ip': event.get('source_ip', '?'),
                        'path': unquote(path)[:200],
                        'description': f'XSS attempt from {event.get("source_ip", "?")} on path: {unquote(path)[:100]}'
                    })
                    break

    return alerts


def correlate_attack_chain(events):
    """Correlate events into potential attack chains."""
    chains = []

    # Look for: failed logins → successful login → privilege escalation
    by_ip = defaultdict(list)
    for event in events:
        if 'source_ip' in event:
            by_ip[event['source_ip']].append(event)

    for ip, ip_events in by_ip.items():
        failed = [e for e in ip_events if e.get('event') == 'failed_login']
        success = [e for e in ip_events if e.get('event') in ('accepted_login', 'success_login')]
        priv_esc = [e for e in ip_events if e.get('event') == 'privilege_escalation']

        if len(failed) >= 3 and success:
            chain = {
                'type': 'brute_force_success',
                'severity': 'critical',
                'source_ip': ip,
                'stages': [
                    f'Reconnaissance: {len(failed)} failed login attempts',
                    f'Compromise: Successful login after brute-force',
                ],
                'description': f'Attacker at {ip} brute-forced credentials ({len(failed)} attempts) then successfully logged in'
            }
            if priv_esc:
                chain['stages'].append(f'Privilege escalation: {len(priv_esc)} privilege events')
                chain['description'] += f' then escalated privileges'
            chains.append(chain)

    # Look for: directory enumeration → SQLi attempt
    http_events = [e for e in events if e.get('event') == 'http_request']
    by_ip_http = defaultdict(list)
    for event in http_events:
        by_ip_http[event.get('source_ip', '?')].append(event)

    for ip, ip_events in by_ip_http.items():
        enum_count = sum(1 for e in ip_events if e.get('status') == 404)
        sqli_attempts = [e for e in ip_events if re.search(r'union|select|\'\s*or|1=1', e.get('path', ''), re.I)]

        if enum_count > 10 and sqli_attempts:
            chains.append({
                'type': 'web_app_attack',
                'severity': 'high',
                'source_ip': ip,
                'stages': [
                    f'Reconnaissance: {enum_count} requests resulting in 404 (directory enumeration)',
                    f'Exploitation: {len(sqli_attempts)} SQL injection attempts'
                ],
                'description': f'Attacker at {ip} enumerated directories then attempted SQL injection'
            })

    return chains


def analyze_logs(log_content, log_type='ssh'):
    """Main function: analyze a batch of log lines."""
    if not log_content:
        return {'error': 'No log content provided'}

    lines = log_content.strip().split('\n')
    events = []
    parse_errors = 0

    for line in lines:
        parsed = parse_log_line(line, log_type)
        if parsed:
            events.append(parsed)
        elif line.strip():
            parse_errors += 1

    # Run all detection modules
    brute_force = detect_brute_force(events)
    impossible_travel = detect_impossible_travel(events)
    priv_esc = detect_privilege_escalation(events)
    suspicious_http = detect_suspicious_http_activity(events)
    attack_chains = correlate_attack_chain(events)

    # Combine all alerts
    all_alerts = brute_force + impossible_travel + priv_esc + suspicious_http

    # Calculate overall threat level
    critical_count = sum(1 for a in all_alerts if a.get('severity') == 'critical')
    high_count = sum(1 for a in all_alerts if a.get('severity') == 'high')
    medium_count = sum(1 for a in all_alerts if a.get('severity') == 'medium')

    if critical_count or attack_chains:
        threat_level = 'CRITICAL'
    elif high_count >= 3:
        threat_level = 'HIGH'
    elif high_count or medium_count >= 5:
        threat_level = 'MEDIUM'
    elif medium_count:
        threat_level = 'LOW'
    else:
        threat_level = 'NORMAL'

    # Event summary
    event_counts = defaultdict(int)
    for event in events:
        event_counts[event.get('event', 'unknown')] += 1

    return {
        'timestamp': datetime.now().isoformat(),
        'log_type': log_type,
        'total_lines': len(lines),
        'events_parsed': len(events),
        'parse_errors': parse_errors,
        'threat_level': threat_level,
        'event_summary': dict(event_counts),
        'alerts': {
            'brute_force': brute_force,
            'impossible_travel': impossible_travel,
            'privilege_escalation': priv_esc,
            'suspicious_http': suspicious_http,
        },
        'attack_chains': attack_chains,
        'total_alerts': len(all_alerts),
        'critical_alerts': critical_count,
        'high_alerts': high_count,
        'medium_alerts': medium_count,
        'recommendations': generate_recommendations(all_alerts, attack_chains, threat_level)
    }


def generate_recommendations(alerts, chains, threat_level):
    """Generate security recommendations based on findings."""
    recs = []
    alert_types = {a['type'] for a in alerts}

    if 'brute_force' in alert_types:
        recs.append('Implement account lockout after 5 failed attempts')
        recs.append('Enable fail2ban or similar IP blocking on SSH')
        recs.append('Switch to key-based SSH authentication (disable password auth)')

    if 'impossible_travel' in alert_types:
        recs.append('Implement geo-IP restrictions for user logins')
        recs.append('Require MFA for all remote access')
        recs.append('Configure impossible-travel detection in your SIEM')

    if 'privilege_escalation' in alert_types:
        recs.append('CRITICAL: Review all privilege escalation events immediately')
        recs.append('Audit user group memberships and admin accounts')
        recs.append('Implement least-privilege access control')

    if 'sqli_attempt' in alert_types:
        recs.append('Patch web application — use parameterized queries')
        recs.append('Deploy a WAF (Web Application Firewall)')
        recs.append('Review and sanitize all input parameters')

    if 'xss_attempt' in alert_types:
        recs.append('Implement output encoding for all user input')
        recs.append('Add Content Security Policy headers')
        recs.append('Use a modern framework with automatic XSS protection')

    if 'directory_enumeration' in alert_types:
        recs.append('Block IPs with excessive 404 responses')
        recs.append('Disable directory listing on web servers')

    if chains:
        recs.append(f'CRITICAL: {len(chains)} attack chain(s) detected — investigate immediately')
        recs.append('Review all activity from flagged source IPs')

    if threat_level == 'NORMAL':
        recs.append('No significant threats detected. Continue monitoring.')

    return recs
