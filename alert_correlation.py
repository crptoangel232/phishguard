"""
Alert Correlation Engine — SIEM Component

Rule-based alert correlation, deduplication, and aggregation.
Reduces alert fatigue by grouping related alerts into incidents,
suppression rules, and intelligent aggregation.
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict


# Correlation strategies
CORRELATION_STRATEGIES = {
    'same_source_ip': 'Group alerts from the same source IP within a time window',
    'same_target': 'Group alerts targeting the same system/user',
    'same_mitre_tactic': 'Group alerts using the same MITRE ATT&CK tactic',
    'kill_chain_progression': 'Group alerts that form a kill chain progression',
    'duplicate_suppression': 'Suppress duplicate alerts for the same issue',
}


class AlertCorrelationEngine:
    """Correlates, deduplicates, and aggregates SIEM alerts into incidents."""

    def __init__(self, time_window_minutes=30):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.raw_alerts = []
        self.incidents = []
        self.suppressed = 0
        self.aggregated = 0

    def ingest_alerts(self, alerts):
        """Ingest alerts from the SIEM engine for correlation."""
        self.raw_alerts.extend(alerts)
        self._correlate()
        return self.get_incidents()

    def _correlate(self):
        """Run all correlation strategies."""
        # Sort alerts by time
        self.raw_alerts.sort(key=lambda a: a.get('triggered_at', ''))

        used = set()
        incidents = []

        # Strategy 1: Same source IP + time window
        ip_groups = defaultdict(list)
        for i, alert in enumerate(self.raw_alerts):
            if i in used:
                continue
            ip = alert.get('source_ip', 'unknown')
            ip_groups[ip].append((i, alert))

        for ip, ip_alerts in ip_groups.items():
            if len(ip_alerts) < 2:
                continue

            # Group by time window
            cluster = []
            for i, alert in ip_alerts:
                if i in used:
                    continue
                alert_time = self._parse_time(alert.get('triggered_at', ''))
                if not cluster:
                    cluster = [(i, alert, alert_time)]
                else:
                    last_time = cluster[-1][2]
                    if alert_time and last_time and (alert_time - last_time) <= self.time_window:
                        cluster.append((i, alert, alert_time))
                    else:
                        if len(cluster) >= 2:
                            incidents.append(self._create_incident(
                                cluster, 'same_source_ip',
                                f'Multiple alerts from {ip} within {self.time_window.seconds//60}min window'
                            ))
                            for idx, _, _ in cluster:
                                used.add(idx)
                        cluster = [(i, alert, alert_time)]

            if len(cluster) >= 2:
                incidents.append(self._create_incident(
                    cluster, 'same_source_ip',
                    f'Multiple alerts from {ip} within {self.time_window.seconds//60}min window'
                ))
                for idx, _, _ in cluster:
                    used.add(idx)

        # Strategy 2: Kill chain progression
        remaining = [(i, a) for i, a in enumerate(self.raw_alerts) if i not in used]
        kill_chain_groups = defaultdict(list)

        for i, alert in remaining:
            mitre = alert.get('mitre', '')
            # Map MITRE to kill chain phase
            phase = self._mitre_to_phase(mitre)
            if phase:
                kill_chain_groups[phase].append((i, alert))

        # Look for progression: recon → exploit → C2 → exfil
        phase_order = ['reconnaissance', 'exploitation', 'installation', 'command_and_control', 'exfiltration']
        phases_present = sorted(kill_chain_groups.keys(), key=lambda p: phase_order.index(p) if p in phase_order else 99)

        if len(phases_present) >= 2:
            chain_alerts = []
            for phase in phases_present:
                for i, alert in kill_chain_groups[phase][:2]:
                    if i not in used:
                        chain_alerts.append((i, alert))
                        used.add(i)

            if len(chain_alerts) >= 2:
                incidents.append(self._create_incident(
                    [(i, a, None) for i, a in chain_alerts],
                    'kill_chain_progression',
                    f'Kill chain progression: {" → ".join(phases_present)}'
                ))

        # Strategy 3: Duplicate suppression
        remaining = [(i, a) for i, a in enumerate(self.raw_alerts) if i not in used]
        seen = set()
        for i, alert in remaining:
            key = f"{alert.get('rule_id')}:{alert.get('source_ip')}:{alert.get('severity')}"
            if key in seen:
                self.suppressed += 1
                used.add(i)
            else:
                seen.add(key)

        # Remaining uncorrelated alerts become single-alert incidents
        for i, alert in enumerate(self.raw_alerts):
            if i not in used:
                incidents.append(self._create_incident(
                    [(i, alert, None)], 'standalone',
                    f'Individual alert: {alert.get("rule_name", "Unknown")}'
                ))
                used.add(i)

        self.incidents = incidents
        self.aggregated = sum(1 for inc in incidents if len(inc['alerts']) > 1)

    def _parse_time(self, time_str):
        """Parse timestamp string."""
        formats = ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%SZ']
        for fmt in formats:
            try:
                return datetime.strptime(time_str[:26].rstrip('Z'), fmt)
            except (ValueError, TypeError):
                continue
        return None

    def _mitre_to_phase(self, mitre):
        """Map MITRE technique to kill chain phase."""
        mapping = {
            'T1046': 'reconnaissance', 'T1087': 'reconnaissance',
            'T1110': 'exploitation', 'T1078': 'exploitation',
            'T1059': 'exploitation', 'T1190': 'exploitation', 'T1003': 'exploitation',
            'T1053': 'installation', 'T1547': 'installation', 'T1136': 'installation', 'T1098': 'installation',
            'T1071': 'command_and_control',
            'T1041': 'exfiltration', 'T1567': 'exfiltration',
            'T1486': 'impact',
            'T1548': 'exploitation',
            'T1185': 'exploitation',
        }
        return mapping.get(mitre)

    def _create_incident(self, cluster, strategy, description):
        """Create a correlated incident from a cluster of alerts."""
        alerts = [c[1] for c in cluster]
        severity = max(alerts, key=lambda a: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(a.get('severity', 'low'), 0))

        return {
            'incident_id': f'INC-{len(self.incidents) + 1:04d}',
            'strategy': strategy,
            'description': description,
            'severity': severity.get('severity', 'low'),
            'alert_count': len(alerts),
            'source_ips': list(set(a.get('source_ip', 'unknown') for a in alerts)),
            'mitre_techniques': list(set(a.get('mitre', 'N/A') for a in alerts if a.get('mitre', 'N/A') != 'N/A')),
            'rules_triggered': list(set(a.get('rule_name', 'Unknown') for a in alerts)),
            'first_alert': alerts[0].get('triggered_at', ''),
            'last_alert': alerts[-1].get('triggered_at', ''),
            'alerts': [{'alert_id': a.get('alert_id', ''), 'rule_name': a.get('rule_name', ''),
                       'severity': a.get('severity', ''), 'source_ip': a.get('source_ip', '')} for a in alerts],
            'recommended_action': self._recommend_action(strategy, severity.get('severity', 'low')),
            'status': 'open'
        }

    def _recommend_action(self, strategy, severity):
        """Generate recommended action based on correlation strategy and severity."""
        actions = {
            'same_source_ip': {
                'critical': 'Immediately block all source IPs. Initiate full incident response.',
                'high': 'Block source IP(s) at firewall. Investigate all alert sources.',
                'medium': 'Add source IPs to watchlist. Monitor for escalation.',
                'low': 'Log for trend analysis. No immediate action needed.'
            },
            'kill_chain_progression': {
                'critical': 'CRITICAL: Active attack in progress. Activate IR team immediately.',
                'high': 'Attack progression detected. Contain and investigate all phases.',
                'medium': 'Partial attack pattern. Review and harden defenses.',
                'low': 'Monitor for further progression. Review security controls.'
            },
            'standalone': {
                'critical': 'Investigate immediately. May escalate.',
                'high': 'Review alert and determine if part of larger attack.',
                'medium': 'Monitor for related activity.',
                'low': 'Log for trend analysis.'
            }
        }
        return actions.get(strategy, actions['standalone']).get(severity, 'Review and monitor.')

    def get_incidents(self):
        """Get all correlated incidents."""
        return {
            'timestamp': datetime.now().isoformat(),
            'total_raw_alerts': len(self.raw_alerts),
            'total_incidents': len(self.incidents),
            'aggregated_incidents': self.aggregated,
            'suppressed_duplicates': self.suppressed,
            'alerts_remaining': len(self.raw_alerts) - self.suppressed,
            'incidents': sorted(self.incidents, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x['severity'], 4)),
            'top_incidents': sorted(self.incidents, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x['severity'], 4))[:5]
        }
