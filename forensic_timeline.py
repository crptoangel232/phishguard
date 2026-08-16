"""
Forensic Timeline Builder — Incident Response Tool

Parses system logs, file metadata, and network events to build a chronological
attack timeline. Maps events to the Cyber Kill Chain and MITRE ATT&CK framework.
"""

import re
from datetime import datetime
from collections import defaultdict


# Kill Chain phases (Lockheed Martin)
KILL_CHAIN_PHASES = {
    'reconnaissance': {
        'label': '1. Reconnaissance',
        'description': 'Attacker gathers information about the target',
        'mitre_tactics': ['TA0043'],
        'color': '#4CAF50'
    },
    'weaponization': {
        'label': '2. Weaponization',
        'description': 'Attacker creates exploit and payload',
        'mitre_tactics': ['TA0042'],
        'color': '#8BC34A'
    },
    'delivery': {
        'label': '3. Delivery',
        'description': 'Attack payload is transmitted to the target',
        'mitre_tactics': ['TA0001'],
        'color': '#CDDC39'
    },
    'exploitation': {
        'label': '4. Exploitation',
        'description': 'Attack payload is executed on the target',
        'mitre_tactics': ['TA0002'],
        'color': '#FFEB3B'
    },
    'installation': {
        'label': '5. Installation',
        'description': 'Attacker installs tools or backdoors',
        'mitre_tactics': ['TA0003'],
        'color': '#FFC107'
    },
    'command_and_control': {
        'label': '6. Command & Control',
        'description': 'Attacker establishes remote control channel',
        'mitre_tactics': ['TA0011'],
        'color': '#FF9800'
    },
    'actions_on_objectives': {
        'label': '7. Actions on Objectives',
        'description': 'Attacker achieves their goal (data theft, destruction, etc.)',
        'mitre_tactics': ['TA0040', 'TA0010'],
        'color': '#F44336'
    }
}

# MITRE ATT&CK technique patterns
ATTACK_TECHNIQUES = {
    'T1110': {'name': 'Brute Force', 'tactic': 'credential_access', 'kill_chain': 'exploitation',
              'pattern': r'Failed password|brute.?force|password.?spray|credential.?stuffing'},
    'T1078': {'name': 'Valid Accounts', 'tactic': 'defense_evasion', 'kill_chain': 'exploitation',
              'pattern': r'Accepted password|Logon Success|successful login'},
    'T1059': {'name': 'Command and Scripting', 'tactic': 'execution', 'kill_chain': 'exploitation',
              'pattern': r'cmd\.exe|powershell|/bin/bash|python.*-c|perl.*-e'},
    'T1046': {'name': 'Network Service Scan', 'tactic': 'discovery', 'kill_chain': 'reconnaissance',
              'pattern': r'nmap|masscan|port\s*scan|syn\s*scan|service\s*detection'},
    'T1190': {'name': 'Exploit Public-Facing App', 'tactic': 'initial_access', 'kill_chain': 'exploitation',
              'pattern': r'SQL.?injection|XSS|CVE-\d{4}-\d+|remote.?code.?execution|RCE'},
    'T1053': {'name': 'Scheduled Task/Job', 'tactic': 'execution', 'kill_chain': 'installation',
              'pattern': r'crontab|schtasks|at\s+\d|systemd.?timer|launchd'},
    'T1547': {'name': 'Boot or Logon Autostart', 'tactic': 'persistence', 'kill_chain': 'installation',
              'pattern': r'registry|HKLM|HKCU|\.bashrc|\.bash_profile|/etc/rc\.local|startup'},
    'T1071': {'name': 'Application Layer Protocol', 'tactic': 'command_and_control', 'kill_chain': 'command_and_control',
              'pattern': r'beacon|callback|C2|command.?and.?control|dns.?tunnel|http.?tunnel'},
    'T1041': {'name': 'Exfiltration Over C2 Channel', 'tactic': 'exfiltration', 'kill_chain': 'actions_on_objectives',
              'pattern': r'exfil|data.?transfer|upload.*sensitive|large.?outbound'},
    'T1567': {'name': 'Exfiltration Over Web Service', 'tactic': 'exfiltration', 'kill_chain': 'actions_on_objectives',
              'pattern': r'upload|dropbox|mega\.nz|google.?drive|pastebin|transfer\.sh'},
    'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'impact', 'kill_chain': 'actions_on_objectives',
              'pattern': r'encrypt|ransom|locked.*files|\.encrypted|bitcoin.?wallet|payment.?demand'},
    'T1003': {'name': 'OS Credential Dumping', 'tactic': 'credential_access', 'kill_chain': 'exploitation',
              'pattern': r'mimikatz|lsass|SAM|/etc/shadow|credential.?dump|hashdump'},
    'T1098': {'name': 'Account Manipulation', 'tactic': 'persistence', 'kill_chain': 'installation',
              'pattern': r'useradd|usermod|net user|account.*created|privilege.*escalat'},
    'T1087': {'name': 'Account Discovery', 'tactic': 'discovery', 'kill_chain': 'reconnaissance',
              'pattern': r'whoami|id\b|w\b|last\b|net user|/etc/passwd|enum'},
}


def classify_event(event_text):
    """Classify an event into a kill chain phase and MITRE technique."""
    event_lower = event_text.lower()

    detected = []
    for tech_id, tech_info in ATTACK_TECHNIQUES.items():
        if re.search(tech_info['pattern'], event_lower, re.IGNORECASE):
            detected.append({
                'technique_id': tech_id,
                'technique_name': tech_info['name'],
                'tactic': tech_info['tactic'],
                'kill_chain_phase': tech_info['kill_chain'],
            })

    return detected


def parse_timestamp(ts_str):
    """Parse various timestamp formats."""
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%SZ',
        '%b %d %H:%M:%S',  # Syslog format
        '%d/%b/%Y:%H:%M:%S',  # Apache format
        '%Y-%m-%d %H:%M:%S.%f',
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def build_timeline(events):
    """
    Build a forensic timeline from a list of event dictionaries.
    Each event should have: timestamp (str), description (str), source (str optional)
    """
    timeline = []

    for event in events:
        ts_str = event.get('timestamp', '')
        desc = event.get('description', event.get('message', event.get('raw', '')))
        source = event.get('source', event.get('host', 'unknown'))

        ts = parse_timestamp(ts_str)

        # Classify the event
        classifications = classify_event(desc)

        timeline_entry = {
            'timestamp': ts_str,
            'parsed_time': ts.isoformat() if ts else None,
            'description': desc[:300],
            'source': source,
            'classifications': classifications,
            'kill_chain_phases': list(set(c['kill_chain_phase'] for c in classifications)),
            'techniques': list(set(c['technique_id'] for c in classifications)),
            'sort_key': ts.isoformat() if ts else ts_str
        }
        timeline.append(timeline_entry)

    # Sort chronologically
    timeline.sort(key=lambda x: x['sort_key'])

    # Analyze kill chain coverage
    kill_chain_progression = analyze_kill_chain(timeline)

    # Identify attack narrative
    narrative = generate_narrative(timeline, kill_chain_progression)

    return {
        'timestamp': datetime.now().isoformat(),
        'total_events': len(timeline),
        'timeline': timeline,
        'kill_chain_analysis': kill_chain_progression,
        'attack_narrative': narrative,
        'mitre_techniques': list(set(t for entry in timeline for t in entry['techniques']))
    }


def analyze_kill_chain(timeline):
    """Analyze which kill chain phases are represented."""
    phases_present = set()
    phase_events = defaultdict(list)

    for entry in timeline:
        for phase in entry['kill_chain_phases']:
            phases_present.add(phase)
            phase_events[phase].append({
                'timestamp': entry['timestamp'],
                'description': entry['description'][:100],
                'techniques': entry['techniques']
            })

    # Build progression
    progression = []
    phase_order = ['reconnaissance', 'weaponization', 'delivery', 'exploitation',
                   'installation', 'command_and_control', 'actions_on_objectives']

    for phase in phase_order:
        phase_info = KILL_CHAIN_PHASES[phase]
        is_present = phase in phases_present
        progression.append({
            'phase': phase,
            'label': phase_info['label'],
            'description': phase_info['description'],
            'present': is_present,
            'event_count': len(phase_events.get(phase, [])),
            'events': phase_events.get(phase, [])[:5],  # Top 5 events
            'color': phase_info['color']
        })

    # Calculate completeness
    completed_phases = len(phases_present)
    total_phases = len(phase_order)
    completeness = f'{completed_phases}/{total_phases} phases'

    # Determine attack stage
    if 'actions_on_objectives' in phases_present:
        attack_stage = 'COMPLETE — Attack reached final objective'
        severity = 'critical'
    elif 'command_and_control' in phases_present:
        attack_stage = 'C2 ESTABLISHED — Attacker has remote access'
        severity = 'critical'
    elif 'installation' in phases_present:
        attack_stage = 'PERSISTENCE — Attacker maintaining access'
        severity = 'high'
    elif 'exploitation' in phases_present:
        attack_stage = 'EXPLOITED — Vulnerability exploited'
        severity = 'high'
    elif 'delivery' in phases_present:
        attack_stage = 'DELIVERED — Payload transmitted, may not have executed'
        severity = 'medium'
    elif 'reconnaissance' in phases_present:
        attack_stage = 'RECONNAISSANCE — Information gathering detected'
        severity = 'medium'
    else:
        attack_stage = 'UNKNOWN — No clear attack pattern'
        severity = 'low'

    return {
        'progression': progression,
        'completeness': completeness,
        'attack_stage': attack_stage,
        'severity': severity,
        'phases_detected': list(phases_present)
    }


def generate_narrative(timeline, kill_chain_analysis):
    """Generate a human-readable attack narrative."""
    if not timeline:
        return 'No events to analyze.'

    narrative_parts = []
    narrative_parts.append(f'FORENSIC TIMELINE: {len(timeline)} events analyzed.')
    narrative_parts.append(f'KILL CHAIN: {kill_chain_analysis["completeness"]} detected.')
    narrative_parts.append(f'CURRENT STAGE: {kill_chain_analysis["attack_stage"]}')

    # Add key events
    classified_events = [e for e in timeline if e['classifications']]
    if classified_events:
        narrative_parts.append(f'\nKEY MALICIOUS ACTIVITY ({len(classified_events)} events):')
        for event in classified_events[:10]:
            techniques = ', '.join(event['techniques']) if event['techniques'] else 'uncategorized'
            narrative_parts.append(f'  [{event["timestamp"]}] {event["description"][:100]} ({techniques})')

    # Add MITRE techniques
    all_techs = set()
    for entry in timeline:
        all_techs.update(entry.get('techniques', []))
    if all_techs:
        narrative_parts.append(f'\nMITRE ATT&CK TECHNIQUES: {", ".join(sorted(all_techs))}')

    return '\n'.join(narrative_parts)


def parse_raw_logs(log_content, log_type='ssh'):
    """Parse raw log lines into events for the timeline builder."""
    from log_analyzer import parse_log_line

    events = []
    for line in log_content.strip().split('\n'):
        parsed = parse_log_line(line, log_type)
        if parsed:
            events.append({
                'timestamp': parsed.get('timestamp_str', ''),
                'description': parsed.get('message', parsed.get('raw', '')),
                'source': parsed.get('source_ip', parsed.get('host', 'unknown')),
                'event_type': parsed.get('event', 'unknown'),
                'raw': parsed.get('raw', line)
            })

    return build_timeline(events)
