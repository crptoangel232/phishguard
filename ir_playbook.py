"""
IR Playbook Engine — Incident Response Tool

Generates incident response playbooks based on NIST SP 800-61 guidelines.
When an alert fires, provides step-by-step response procedures for containment,
eradication, recovery, and post-incident analysis.
"""

from datetime import datetime


# NIST SP 800-61 Incident Response Life Cycle
NIST_PHASES = {
    'preparation': {
        'label': '1. Preparation',
        'description': 'Establish tools, procedures, and team before incidents occur',
        'order': 1
    },
    'detection_analysis': {
        'label': '2. Detection & Analysis',
        'description': 'Detect the incident, determine scope and impact',
        'order': 2
    },
    'containment': {
        'label': '3. Containment',
        'description': 'Limit the spread and damage of the incident',
        'order': 3
    },
    'eradication': {
        'label': '4. Eradication',
        'description': 'Remove the cause and eliminate the threat',
        'order': 4
    },
    'recovery': {
        'label': '5. Recovery',
        'description': 'Restore systems to normal operation',
        'order': 5
    },
    'post_incident': {
        'label': '6. Post-Incident Activity',
        'description': 'Document lessons learned and improve defenses',
        'order': 6
    }
}


# Incident type templates
INCIDENT_TEMPLATES = {
    'phishing': {
        'name': 'Phishing Attack Response',
        'severity': 'medium',
        'steps': {
            'detection_analysis': [
                'Verify the phishing URL/email is malicious using PhishGuard URL detector',
                'Identify all recipients who received the phishing message',
                'Check email logs for delivery status (delivered, opened, clicked)',
                'Determine if any credentials were entered on the phishing site',
                'Assess if any attachments were downloaded and executed'
            ],
            'containment': [
                'Block the phishing domain/IP at the email gateway and firewall',
                'Recall or quarantine the phishing email from all mailboxes',
                'Force password reset for any users who clicked the link',
                'Revoke active sessions for affected users',
                'Block the sender domain in email security platform'
            ],
            'eradication': [
                'Verify no malware was installed by phishing payload',
                'Scan affected systems with endpoint detection (EDR)',
                'Remove any downloaded malicious files',
                'Check for credential reuse on other systems'
            ],
            'recovery': [
                'Confirm all affected accounts have new passwords',
                'Verify email filtering rules are updated',
                'Monitor for follow-up phishing attempts',
                'Send awareness notification to all employees'
            ],
            'post_incident': [
                'Document which users clicked and what information was exposed',
                'Update phishing awareness training materials',
                'Review email security configuration gaps',
                'Add the phishing indicators (domain, IP, sender) to blocklists'
            ]
        }
    },

    'brute_force': {
        'name': 'Brute-Force Attack Response',
        'severity': 'high',
        'steps': {
            'detection_analysis': [
                'Confirm brute-force pattern using the Log Analyzer tool',
                'Identify the source IP(s) and attack duration',
                'Determine if any login attempts succeeded',
                'Check which user accounts were targeted',
                'Assess the number of attempts per account'
            ],
            'containment': [
                'Block the source IP at the firewall immediately',
                'Lock all targeted accounts temporarily',
                'Enable fail2ban or increase rate-limiting rules',
                'If SSH: disable password authentication, enforce key-based only',
                'Increase logging verbosity for the targeted service'
            ],
            'eradication': [
                'Force password reset for all targeted accounts',
                'Review successful logins from the attack timeframe',
                'Check for any unauthorized SSH keys added to authorized_keys',
                'Scan for any backdoor accounts created',
                'Verify no malware was deployed after successful login'
            ],
            'recovery': [
                'Unlock accounts after password reset is complete',
                'Verify all authentication mechanisms are functioning',
                'Monitor for continued attack from new IPs',
                'Review and strengthen password policies'
            ],
            'post_incident': [
                'Document the attack source, duration, and impact',
                'Review why existing controls did not prevent the attack',
                'Implement automated IP blocking for future brute-force attempts',
                'Consider implementing MFA for all external-facing services'
            ]
        }
    },

    'malware': {
        'name': 'Malware Detection Response',
        'severity': 'critical',
        'steps': {
            'detection_analysis': [
                'Identify the malware type using IOC Scanner (hash, filename, behavior)',
                'Determine the infection vector (email, download, lateral movement)',
                'Map infected systems using EDR/network logs',
                'Assess the malware capabilities (ransomware, spyware, trojan, etc.)',
                'Check if the malware has C2 communication (use Network Scanner)'
            ],
            'containment': [
                'Isolate infected systems from the network immediately (do NOT power off)',
                'Disable affected user accounts',
                'Block known C2 domains/IPs at firewall and DNS',
                'Preserve volatile evidence (memory dump) before any cleanup',
                'Segment the network to prevent lateral movement'
            ],
            'eradication': [
                'Remove malware using EDR or endpoint antivirus',
                'Delete persistence mechanisms (scheduled tasks, registry keys, cron jobs)',
                'Remove any malicious files from all affected systems',
                'Patch the vulnerability that allowed initial infection',
                'Verify no backdoor accounts or SSH keys were created'
            ],
            'recovery': [
                'Restore systems from clean backups if needed',
                'Verify all malware is removed with full system scan',
                'Reconnect systems to network in stages (monitor each)',
                'Reset all credentials that may have been exposed',
                'Verify system integrity (file hashes, system binaries)'
            ],
            'post_incident': [
                'Document the full timeline using Forensic Timeline Builder',
                'Determine root cause and initial infection vector',
                'Calculate business impact (downtime, data loss, cost)',
                'Update IOC blocklists with new indicators',
                'Improve detection rules for this malware family',
                'Conduct tabletop exercise to test improved response'
            ]
        }
    },

    'data_breach': {
        'name': 'Data Breach Response',
        'severity': 'critical',
        'steps': {
            'detection_analysis': [
                'Identify what data was accessed or exfiltrated',
                'Determine the breach vector (web exploit, insider, misconfiguration)',
                'Assess the number of records affected',
                'Check if data contains PII, financial, or regulated data',
                'Identify the attacker timeline using Forensic Timeline Builder'
            ],
            'containment': [
                'Sever the attacker\'s access immediately (revoke credentials, close holes)',
                'Isolate affected systems from the network',
                'Preserve all logs and evidence before any changes',
                'Block attacker IPs and C2 channels',
                'Activate crisis communication team if PII is involved'
            ],
            'eradication': [
                'Identify and close the vulnerability that was exploited',
                'Remove any attacker tools, backdoors, or persistence mechanisms',
                'Rotate all credentials that may have been compromised',
                'Patch all systems in the breach path',
                'Verify no data exfiltration is ongoing'
            ],
            'recovery': [
                'Restore systems from verified clean backups',
                'Implement enhanced monitoring on affected systems',
                'Verify data integrity (compare with backups)',
                'Notify affected individuals per regulatory requirements (GDPR 72hrs, etc.)',
                'Engage legal counsel and compliance team'
            ],
            'post_incident': [
                'Conduct full forensic analysis using the timeline builder',
                'Document: what happened, how, what data, who was affected',
                'Assess compliance reporting obligations (GDPR, CCPA, HIPAA, etc.)',
                'Review and improve data protection controls',
                'Implement additional monitoring for the affected data type',
                'Prepare breach notification documentation for regulators'
            ]
        }
    },

    'ransomware': {
        'name': 'Ransomware Attack Response',
        'severity': 'critical',
        'steps': {
            'detection_analysis': [
                'Identify the ransomware variant (check ransom note, file extensions)',
                'Determine the scope of encryption (which systems, which files)',
                'Check IOC Scanner for known ransomware indicators',
                'Identify the initial infection vector',
                'Determine if data was exfiltrated before encryption (double extortion)'
            ],
            'containment': [
                'CRITICAL: Isolate all affected systems IMMEDIATELY — disconnect network cables',
                'DO NOT power off systems — may lose decryption keys in memory',
                'Block the ransomware\'s C2 communication channels',
                'Disable all file shares and backup systems to prevent spread',
                'Preserve the ransom note and any attacker communications',
                'Photograph or screenshot the ransom message'
            ],
            'eradication': [
                'Identify and remove the ransomware binary',
                'Remove persistence mechanisms (startup entries, scheduled tasks)',
                'Patch the vulnerability used for initial access',
                'Verify the ransomware cannot re-execute',
                'Check for any remaining C2 backdoors'
            ],
            'recovery': [
                'Restore from offline/immutable backups (verify they are clean first)',
                'DO NOT pay the ransom unless absolutely no other option',
                'Verify restored data integrity',
                'Reconnect systems in phases with monitoring',
                'Reset all credentials for affected systems'
            ],
            'post_incident': [
                'Build complete forensic timeline of the attack',
                'Report to law enforcement (FBI IC3, local cyber crime unit)',
                'Assess total business impact (downtime, data loss, recovery cost)',
                'Review backup strategy — implement immutable/offline backups',
                'Conduct security gap assessment',
                'Implement ransomware-specific detection rules',
                'Train staff on ransomware prevention'
            ]
        }
    },

    'web_attack': {
        'name': 'Web Application Attack Response',
        'severity': 'high',
        'steps': {
            'detection_analysis': [
                'Identify the attack type using SQLi Detector (SQL injection, XSS, etc.)',
                'Review web server and application logs for attack patterns',
                'Determine if the attack was successful (data access, code execution)',
                'Identify the vulnerable parameter or endpoint',
                'Assess what data could have been exposed'
            ],
            'containment': [
                'Block the attacker IP at the WAF or firewall',
                'Temporarily disable the vulnerable endpoint if possible',
                'Enable WAF rules for the detected attack pattern',
                'Increase logging on the affected web application',
                'If SQLi confirmed: rotate database credentials immediately'
            ],
            'eradication': [
                'Patch the vulnerability in the web application code',
                'Implement parameterized queries if SQLi was the vector',
                'Add input validation and output encoding',
                'Review all similar code patterns for the same vulnerability',
                'Update WAF rules to block this attack pattern permanently'
            ],
            'recovery': [
                'Verify the patched application handles the attack payloads correctly',
                'Run automated security testing against the fixed endpoint',
                'Review database for any unauthorized access or data extraction',
                'Monitor for follow-up attacks from different IPs',
                'Restore any tampered data from backups'
            ],
            'post_incident': [
                'Document the vulnerability and how it was exploited',
                'Conduct full web application security assessment',
                'Implement SAST/DAST in the CI/CD pipeline',
                'Update secure coding guidelines',
                'Add automated tests for this vulnerability class'
            ]
        }
    },

    'insider_threat': {
        'name': 'Insider Threat Response',
        'severity': 'high',
        'steps': {
            'detection_analysis': [
                'Identify the suspected insider and their access level',
                'Review their activity logs for anomalous behavior (after hours, large downloads)',
                'Check for data exfiltration (USB, email, cloud uploads)',
                'Review privilege escalation attempts',
                'Determine if this is malicious or accidental'
            ],
            'containment': [
                'Suspend the user\'s access to sensitive systems (coordinate with HR)',
                'Preserve all logs and evidence before confronting the user',
                'Monitor their account for any automated tasks they may have set',
                'Do NOT alert the user that they are under investigation',
                'Secure any physical access if applicable'
            ],
            'eradication': [
                'Revoke all access credentials (passwords, keys, tokens, VPN)',
                'Review and remove any access they granted to others',
                'Check for any backdoors or scheduled tasks created by the user',
                'Recover any exfiltrated data if possible',
                'Review all changes made by the user in the last 90 days'
            ],
            'recovery': [
                'Restore any modified or deleted data',
                'Verify no unauthorized access persists',
                'Review and tighten access controls for the affected systems',
                'Implement additional monitoring for similar patterns',
                'Coordinate with HR/Legal on employment status'
            ],
            'post_incident': [
                'Document the full activity timeline',
                'Review access management policies',
                'Implement behavioral analytics for early detection',
                'Conduct security awareness training',
                'Review need-to-know access principles'
            ]
        }
    },

    'network_scan': {
        'name': 'Network Scan / Reconnaissance Response',
        'severity': 'low',
        'steps': {
            'detection_analysis': [
                'Use the Network Scanner to verify exposed services',
                'Determine the scanning source and pattern',
                'Assess if the scan preceded an attack',
                'Check if any scans found exploitable services',
                'Review firewall logs for the scanning period'
            ],
            'containment': [
                'Block the scanning IP if it is not a known security scanner',
                'Close any unnecessarily open ports found during the scan',
                'Enable port scan detection on the IDS/IPS',
                'Verify firewall rules are properly configured'
            ],
            'eradication': [
                'Harden any services that were discovered during the scan',
                'Review and close unnecessary open ports',
                'Update service banners to not reveal version information',
                'Patch any services running outdated versions'
            ],
            'recovery': [
                'Verify all unnecessary ports are closed',
                'Confirm services are properly firewalled',
                'Monitor for follow-up activity from the same IP range'
            ],
            'post_incident': [
                'Document the scan pattern and source',
                'Review external-facing service inventory',
                'Consider implementing a honeypot for early detection',
                'Schedule regular external security scans'
            ]
        }
    }
}


def generate_playbook(incident_type, context=None):
    """Generate a complete incident response playbook for the given incident type."""
    incident_type = incident_type.lower().replace('-', '_').replace(' ', '_')

    # Normalize common names
    aliases = {
        'sql_injection': 'web_attack', 'sqli': 'web_attack', 'xss': 'web_attack',
        'port_scan': 'network_scan', 'recon': 'network_scan',
        'credential_theft': 'phishing', 'social_engineering': 'phishing',
        'credential_stuffing': 'brute_force', 'password_attack': 'brute_force',
        'trojan': 'malware', 'virus': 'malware', 'backdoor': 'malware', 'cryptominer': 'malware',
        'leak': 'data_breach', 'exfiltration': 'data_breach',
    }
    if incident_type in aliases:
        incident_type = aliases[incident_type]

    if incident_type not in INCIDENT_TEMPLATES:
        available = ', '.join(INCIDENT_TEMPLATES.keys())
        return {
            'error': f'Unknown incident type: {incident_type}',
            'available_types': available
        }

    template = INCIDENT_TEMPLATES[incident_type]
    playbook = {
        'incident_type': incident_type,
        'playbook_name': template['name'],
        'severity': template['severity'],
        'generated_at': datetime.now().isoformat(),
        'framework': 'NIST SP 800-61 Rev. 2',
        'phases': {},
        'quick_actions': [],
        'evidence_checklist': [],
        'contacts': {}
    }

    # Build phases
    for phase_key, phase_info in NIST_PHASES.items():
        steps = template['steps'].get(phase_key, [])
        if steps:
            playbook['phases'][phase_key] = {
                'label': phase_info['label'],
                'description': phase_info['description'],
                'order': phase_info['order'],
                'steps': steps,
                'completed': False
            }

    # Quick actions (top priority items)
    containment_steps = template['steps'].get('containment', [])
    playbook['quick_actions'] = containment_steps[:3]

    # Evidence checklist
    playbook['evidence_checklist'] = [
        'Capture network traffic (pcap) from affected systems',
        'Take memory dump of affected systems before reboot',
        'Preserve all relevant log files (system, application, network)',
        'Document timestamps of all actions taken',
        'Screenshot any attacker messages or ransom notes',
        'Record all IPs, domains, and hashes involved',
        'Maintain chain of custody for all evidence'
    ]

    # Response contacts (to be filled)
    playbook['contacts'] = {
        'IR Team Lead': '________________',
        'Security Operations': '________________',
        'Legal Counsel': '________________',
        'HR (if insider threat)': '________________',
        'External IR Firm': '________________',
        'Law Enforcement': '________________',
        'Communications/PR': '________________',
        'Executive Sponsor': '________________'
    }

    # Add context-specific adjustments
    if context:
        playbook['context'] = context
        if context.get('source_ip'):
            playbook['quick_actions'].insert(0, f'Block source IP: {context["source_ip"]}')
        if context.get('affected_systems'):
            playbook['quick_actions'].insert(0, f'Isolate affected systems: {", ".join(context["affected_systems"])}')

    return playbook


def list_incident_types():
    """List all available incident types."""
    types = []
    for key, template in INCIDENT_TEMPLATES.items():
        types.append({
            'type': key,
            'name': template['name'],
            'severity': template['severity']
        })
    return types
