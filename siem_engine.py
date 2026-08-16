"""
Mini-SIEM Dashboard — Security Information & Event Management

Central log aggregation from multiple sources, real-time alerting with
correlation rules, threat scoring, and a dashboard summary. Integrates with
the Log Analyzer for event parsing and the Alert Correlation Engine.
"""

from datetime import datetime, timedelta
from collections import defaultdict
import json


class SIEMEngine:
    """Core SIEM engine for log aggregation, correlation, and alerting."""

    def __init__(self):
        self.events = []
        self.alerts = []
        self.alert_rules = self._default_rules()
        self.correlated_incidents = []
        self.sources = set()
        self.metrics = {
            'events_per_minute': 0,
            'alerts_triggered': 0,
            'critical_alerts': 0,
            'high_alerts': 0,
            'medium_alerts': 0,
            'low_alerts': 0,
        }

    def _default_rules(self):
        """Default SIEM correlation rules."""
        return [
            {
                'id': 'RULE-001',
                'name': 'Brute Force SSH',
                'description': '5+ failed SSH logins from same IP within 10 minutes',
                'severity': 'high',
                'condition': {'event': 'failed_login', 'count': 5, 'window_minutes': 10, 'group_by': 'source_ip'},
                'mitre': 'T1110',
                'response': 'Block source IP and lock targeted accounts'
            },
            {
                'id': 'RULE-002',
                'name': 'Successful Login After Brute Force',
                'description': 'Successful login from IP that had multiple failed attempts',
                'severity': 'critical',
                'condition': {'event': 'accepted_login', 'requires_prior': {'event': 'failed_login', 'count': 3, 'group_by': 'source_ip'}},
                'mitre': 'T1078',
                'response': 'Immediately investigate the session and lock the account'
            },
            {
                'id': 'RULE-003',
                'name': 'Multiple 404s (Directory Enumeration)',
                'description': '20+ 404 responses from same IP within 5 minutes',
                'severity': 'medium',
                'condition': {'event': 'http_request', 'status': 404, 'count': 20, 'window_minutes': 5, 'group_by': 'source_ip'},
                'mitre': 'T1046',
                'response': 'Rate-limit or block the source IP'
            },
            {
                'id': 'RULE-004',
                'name': 'SQL Injection Attempt',
                'description': 'URL containing SQL injection patterns',
                'severity': 'high',
                'condition': {'event': 'http_request', 'pattern': r"union|select|'\s*or\s*1=1|--"},
                'mitre': 'T1190',
                'response': 'Block source IP, review web application for vulnerability'
            },
            {
                'id': 'RULE-005',
                'name': 'XSS Attempt',
                'description': 'URL containing XSS payloads',
                'severity': 'high',
                'condition': {'event': 'http_request', 'pattern': r"<script|onerror=|onload=|javascript:"},
                'mitre': 'T1185',
                'response': 'Block source IP, review application output encoding'
            },
            {
                'id': 'RULE-006',
                'name': 'Privilege Escalation',
                'description': 'Special privileges assigned (Windows Event 4672)',
                'severity': 'critical',
                'condition': {'event': 'privilege_escalation'},
                'mitre': 'T1548',
                'response': 'Verify if privilege assignment was authorized'
            },
            {
                'id': 'RULE-007',
                'name': 'Account Created',
                'description': 'New account created (Windows Event 4720)',
                'severity': 'medium',
                'condition': {'event': 'account_created'},
                'mitre': 'T1136',
                'response': 'Verify if account creation was authorized'
            },
            {
                'id': 'RULE-008',
                'name': 'Account Locked',
                'description': 'Account locked out (Windows Event 4740)',
                'severity': 'medium',
                'condition': {'event': 'account_locked'},
                'mitre': 'T1110',
                'response': 'Check if lockout is due to brute force attack'
            },
            {
                'id': 'RULE-009',
                'name': 'Impossible Travel',
                'description': 'User logged in from different geographic locations too quickly',
                'severity': 'high',
                'condition': {'event': 'accepted_login', 'detect_impossible_travel': True},
                'mitre': 'T1078',
                'response': 'Require MFA verification, investigate the session'
            },
            {
                'id': 'RULE-010',
                'name': 'Excessive Failed Logins Across Users',
                'description': '10+ failed logins targeting different users from same IP (password spraying)',
                'severity': 'high',
                'condition': {'event': 'failed_login', 'count': 10, 'window_minutes': 5, 'group_by': 'source_ip', 'unique_users': True},
                'mitre': 'T1110',
                'response': 'Block source IP, enable account lockout policies'
            },
        ]

    def ingest_events(self, events):
        """Ingest a batch of events into the SIEM."""
        for event in events:
            event['siem_id'] = len(self.events) + 1
            event['siem_ingested_at'] = datetime.now().isoformat()
            self.events.append(event)
            if event.get('source_ip'):
                self.sources.add(event['source_ip'])

        # Run correlation rules
        self._run_correlation_rules()

        # Update metrics
        self._update_metrics()

    def _run_correlation_rules(self):
        """Evaluate all correlation rules against ingested events."""
        import re as regex_mod

        for rule in self.alert_rules:
            cond = rule['condition']
            matching_events = [e for e in self.events if e.get('event') == cond['event']]

            # Check for pattern match (SQLi, XSS)
            if 'pattern' in cond:
                for event in matching_events:
                    path = event.get('path', event.get('message', ''))
                    if regex_mod.search(cond['pattern'], str(path), regex_mod.IGNORECASE):
                        self._create_alert(rule, [event])

            # Check for count-based rules (brute force, enumeration)
            if 'count' in cond:
                groups = defaultdict(list)
                for event in matching_events:
                    group_key = event.get(cond.get('group_by', 'source_ip'), 'unknown')

                    # For unique_users check (password spraying)
                    if cond.get('unique_users'):
                        user = event.get('username', '?')
                        if user not in [e.get('username') for e in groups[group_key]]:
                            groups[group_key].append(event)
                    else:
                        groups[group_key].append(event)

                for group_key, group_events in groups.items():
                    if len(group_events) >= cond['count']:
                        self._create_alert(rule, group_events, group_key)

            # Check for requires_prior (brute force → success)
            if 'requires_prior' in cond:
                prior = cond['requires_prior']
                prior_events = [e for e in self.events if e.get('event') == prior['event']]
                prior_groups = defaultdict(list)
                for event in prior_events:
                    prior_groups[event.get(prior.get('group_by', 'source_ip'), 'unknown')].append(event)

                for event in matching_events:
                    ip = event.get('source_ip', 'unknown')
                    if len(prior_groups.get(ip, [])) >= prior['count']:
                        self._create_alert(rule, [event] + prior_groups[ip][:3], ip)

            # Check for impossible travel
            if cond.get('detect_impossible_travel'):
                by_user = defaultdict(list)
                for event in matching_events:
                    user = event.get('username', event.get('source_ip', '?'))
                    by_user[user].append(event)

                for user, logins in by_user.items():
                    if len(logins) >= 2:
                        for i in range(1, len(logins)):
                            if logins[i].get('source_ip') != logins[i-1].get('source_ip'):
                                self._create_alert(rule, [logins[i-1], logins[i]], user)

    def _create_alert(self, rule, events, context=None):
        """Create a new alert from a triggered rule."""
        alert = {
            'alert_id': f'ALERT-{len(self.alerts) + 1:04d}',
            'rule_id': rule['id'],
            'rule_name': rule['name'],
            'description': rule['description'],
            'severity': rule['severity'],
            'mitre': rule.get('mitre', 'N/A'),
            'response': rule['response'],
            'triggered_at': datetime.now().isoformat(),
            'event_count': len(events),
            'source_ip': context or events[0].get('source_ip', 'unknown'),
            'events': [{'timestamp': e.get('timestamp_str', e.get('siem_ingested_at', '')),
                       'message': e.get('message', e.get('path', ''))[:100]} for e in events[:5]]
        }

        # Deduplicate (don't create duplicate alerts for same rule + source)
        existing = [a for a in self.alerts if a['rule_id'] == rule['id'] and a['source_ip'] == alert['source_ip']]
        if not existing:
            self.alerts.append(alert)
            self.metrics['alerts_triggered'] += 1
            if rule['severity'] == 'critical': self.metrics['critical_alerts'] += 1
            elif rule['severity'] == 'high': self.metrics['high_alerts'] += 1
            elif rule['severity'] == 'medium': self.metrics['medium_alerts'] += 1
            else: self.metrics['low_alerts'] += 1

    def _update_metrics(self):
        """Update SIEM metrics."""
        if not self.events:
            return

        # Count unique IPs
        self.metrics['unique_source_ips'] = len(self.sources)
        self.metrics['total_events'] = len(self.events)

        # Event type breakdown
        event_types = defaultdict(int)
        for event in self.events:
            event_types[event.get('event', 'unknown')] += 1
        self.metrics['event_type_breakdown'] = dict(event_types)

    def get_dashboard(self):
        """Get the SIEM dashboard summary."""
        # Calculate threat level
        if self.metrics['critical_alerts'] > 0:
            threat_level = 'CRITICAL'
        elif self.metrics['high_alerts'] >= 3:
            threat_level = 'HIGH'
        elif self.metrics['high_alerts'] > 0 or self.metrics['medium_alerts'] >= 5:
            threat_level = 'ELEVATED'
        elif self.metrics['medium_alerts'] > 0:
            threat_level = 'GUARDED'
        else:
            threat_level = 'NORMAL'

        # Top source IPs by event count
        ip_counts = defaultdict(int)
        for event in self.events:
            ip = event.get('source_ip')
            if ip:
                ip_counts[ip] += 1
        top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]

        # Recent events (last 20)
        recent_events = []
        for event in reversed(self.events[-20:]):
            recent_events.append({
                'id': event.get('siem_id'),
                'timestamp': event.get('timestamp_str', event.get('siem_ingested_at', '')),
                'type': event.get('event', 'unknown'),
                'source_ip': event.get('source_ip', ''),
                'message': str(event.get('message', event.get('path', '')))[:150]
            })

        return {
            'timestamp': datetime.now().isoformat(),
            'threat_level': threat_level,
            'metrics': self.metrics,
            'total_alerts': len(self.alerts),
            'active_alerts': [a for a in self.alerts if a['severity'] in ('critical', 'high')][:10],
            'all_alerts': self.alerts[-20:],
            'top_source_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
            'recent_events': recent_events,
            'rules_active': len(self.alert_rules),
            'event_sources': list(self.sources),
        }

    def add_custom_rule(self, rule):
        """Add a custom correlation rule."""
        rule['id'] = f'CUSTOM-{len(self.alert_rules):03d}'
        self.alert_rules.append(rule)
        return rule['id']


def create_siem_instance():
    """Create and return a fresh SIEM engine instance."""
    return SIEMEngine()
