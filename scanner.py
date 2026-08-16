"""
Network Security Scanner Module

Scans targets for open ports, detects services, identifies vulnerabilities,
and generates security reports. Uses Python's built-in socket library — no nmap required.
"""

import socket
import ipaddress
import concurrent.futures
from datetime import datetime

# Common ports and their associated services
COMMON_PORTS = {
    20: ('FTP Data', 'FTP data connection — file transfer'),
    21: ('FTP', 'File Transfer Protocol — plaintext credentials'),
    22: ('SSH', 'Secure Shell — remote access'),
    23: ('Telnet', 'Telnet — insecure remote access (plaintext)'),
    25: ('SMTP', 'Simple Mail Transfer Protocol — email sending'),
    53: ('DNS', 'Domain Name System — name resolution'),
    69: ('TFTP', 'Trivial FTP — insecure file transfer'),
    80: ('HTTP', 'Web server — unencrypted'),
    110: ('POP3', 'Post Office Protocol — email retrieval (plaintext)'),
    111: ('RPC', 'Remote Procedure Call — potential attack surface'),
    119: ('NNTP', 'Network News Transfer Protocol'),
    123: ('NTP', 'Network Time Protocol'),
    135: ('MS RPC', 'Microsoft RPC — Windows service'),
    137: ('NetBIOS', 'NetBIOS Name Service — Windows exposure'),
    138: ('NetBIOS', 'NetBIOS Datagram — Windows exposure'),
    139: ('NetBIOS', 'NetBIOS Session — Windows file sharing'),
    143: ('IMAP', 'Email retrieval — may be plaintext'),
    161: ('SNMP', 'Simple Network Management Protocol — info leakage'),
    162: ('SNMP Trap', 'SNMP Trap — network management'),
    389: ('LDAP', 'Lightweight Directory Access Protocol'),
    443: ('HTTPS', 'Web server — encrypted'),
    445: ('SMB', 'Server Message Block — Windows file sharing (high risk)'),
    465: ('SMTPS', 'SMTP over SSL'),
    587: ('SMTP Submission', 'Email submission with auth'),
    631: ('IPP', 'Internet Printing Protocol — printer exposure'),
    636: ('LDAPS', 'LDAP over SSL'),
    873: ('Rsync', 'Rsync — file synchronization'),
    993: ('IMAPS', 'IMAP over SSL'),
    995: ('POP3S', 'POP3 over SSL'),
    1080: ('SOCKS', 'SOCKS Proxy — potential tunneling'),
    1433: ('MSSQL', 'Microsoft SQL Server — database exposure'),
    1434: ('MSSQL Browser', 'MSSQL Browser Service'),
    1521: ('Oracle DB', 'Oracle Database — database exposure'),
    1723: ('PPTP', 'Point-to-Point Tunneling Protocol — VPN (weak)'),
    2049: ('NFS', 'Network File System — file sharing'),
    2375: ('Docker', 'Docker API — unencrypted (critical risk)'),
    2376: ('Docker TLS', 'Docker API over TLS'),
    3000: ('Node.js/Dev', 'Development server — often Node.js or Grafana'),
    3306: ('MySQL', 'MySQL Database — database exposure'),
    3389: ('RDP', 'Remote Desktop Protocol — high risk if exposed'),
    4000: ('Various', 'Application server'),
    4001: ('Various', 'Application server'),
    4369: ('Erlang', 'Erlang Port Mapper — RabbitMQ'),
    5000: ('Flask/Dev', 'Flask development server or UPnP'),
    5432: ('PostgreSQL', 'PostgreSQL Database — database exposure'),
    5601: ('Kibana', 'Kibana — Elasticsearch UI'),
    5672: ('RabbitMQ', 'RabbitMQ — message queue'),
    5900: ('VNC', 'Virtual Network Computing — remote desktop (plaintext)'),
    5901: ('VNC', 'VNC on display 1'),
    5984: ('CouchDB', 'Apache CouchDB — database exposure'),
    6379: ('Redis', 'Redis — database exposure (often unauthenticated)'),
    6443: ('Kubernetes', 'Kubernetes API — container orchestration'),
    8000: ('HTTP Alt', 'Alternative HTTP — dev servers'),
    8080: ('HTTP Proxy', 'HTTP Proxy or alternative web server'),
    8081: ('HTTP Alt', 'Alternative HTTP'),
    8443: ('HTTPS Alt', 'Alternative HTTPS'),
    8888: ('HTTP Alt', 'Alternative HTTP — Jupyter etc.'),
    9000: ('PHP-FPM', 'PHP FastCGI or SonarQube'),
    9042: ('Cassandra', 'Cassandra CQL'),
    9090: ('Prometheus', 'Prometheus monitoring'),
    9092: ('Kafka', 'Apache Kafka — message broker'),
    9200: ('Elasticsearch', 'Elasticsearch — database exposure'),
    9300: ('Elasticsearch', 'Elasticsearch transport'),
    9418: ('Git', 'Git protocol — repository access'),
    11211: ('Memcached', 'Memcached — cache exposure (often unauthenticated)'),
    15672: ('RabbitMQ UI', 'RabbitMQ Management UI'),
    27017: ('MongoDB', 'MongoDB — database exposure (often unauthenticated)'),
    27018: ('MongoDB', 'MongoDB with auth'),
}

# Vulnerability indicators for specific services
VULNERABILITY_INDICATORS = {
    21: 'FTP sends credentials in plaintext. Use SFTP/SCP over SSH instead.',
    23: 'Telnet transmits all data in plaintext including passwords. Disable immediately and use SSH.',
    80: 'HTTP is unencrypted. Consider redirecting to HTTPS (port 443).',
    110: 'POP3 may transmit credentials in plaintext. Use POP3S (port 995).',
    135: 'MS RPC exposed to external networks. Should be firewalled.',
    137: 'NetBIOS name service exposed. Should not be internet-facing.',
    138: 'NetBIOS datagram exposed. Should not be internet-facing.',
    139: 'NetBIOS session exposed. SMB over NetBIOS is insecure. Use SMB over TCP (port 445) with SMB3.',
    143: 'IMAP may be plaintext. Use IMAPS (port 993).',
    161: 'SNMP can leak system information. Use SNMPv3 with authentication.',
    445: 'SMB exposed to the network. High risk for ransomware and lateral movement. Ensure SMB signing and encryption.',
    512: 'rexec — remote execution. Legacy and insecure. Disable.',
    513: 'rlogin — remote login. Legacy and insecure. Disable.',
    514: 'syslog and rsh. rsh is insecure remote execution. Disable.',
    873: 'Rsync may allow anonymous access. Ensure authentication is required.',
    1080: 'SOCKS proxy can be abused for tunneling. Ensure proper authentication.',
    1433: 'MSSQL exposed externally. Should be firewalled — database ports should not be internet-facing.',
    1521: 'Oracle DB exposed externally. Should be firewalled.',
    1723: 'PPTP has known security weaknesses. Use OpenVPN, WireGuard, or IKEv2.',
    2049: 'NFS exposed. Ensure proper export rules and authentication.',
    2375: 'Docker API without TLS. Critical — attackers can create containers with root access.',
    3000: 'Development server exposed. Should not be production-facing.',
    3306: 'MySQL exposed externally. Database ports should not be internet-facing.',
    3389: 'RDP exposed to the internet. High risk — enable Network Level Authentication and firewall.',
    5000: 'Flask dev server exposed. Use a production WSGI server (gunicorn/uwsgi).',
    5432: 'PostgreSQL exposed externally. Database ports should not be internet-facing.',
    5900: 'VNC transmits in plaintext. Use VNC over SSH or with encryption.',
    5984: 'CouchDB exposed externally. Database ports should not be internet-facing.',
    6379: 'Redis often runs without authentication. Ensure requirepass is set and bind to localhost.',
    8000: 'Dev server exposed. Should not be production-facing.',
    8080: 'Alternative HTTP exposed. Ensure proper authentication and TLS.',
    9200: 'Elasticsearch exposed externally. Often unauthenticated. Should not be internet-facing.',
    11211: 'Memcached often runs without auth. Can be abused for amplification attacks.',
    27017: 'MongoDB exposed externally. Often unauthenticated. High risk of data exposure.',
}

# Security risk levels per port
HIGH_RISK_PORTS = [23, 135, 137, 138, 139, 445, 1433, 1521, 2375, 2376, 2376, 3389, 5432, 5900, 6379, 9200, 11211, 27017]
MEDIUM_RISK_PORTS = [21, 80, 110, 111, 161, 1723, 2049, 5000, 3000, 3000, 8080, 8000, 8888, 9090, 5601, 6443]
LOW_RISK_PORTS = [22, 443, 465, 587, 636, 993, 995, 5672, 15672]


def is_valid_target(target):
    """Validate if the target is a valid IP address or hostname."""
    # Try IP address first
    try:
        ipaddress.ip_address(target)
        return True, target
    except ValueError:
        pass

    # Try hostname resolution
    try:
        socket.gethostbyname(target)
        return True, target
    except socket.gaierror:
        return False, None


def scan_port(host, port, timeout=1.0):
    """Scan a single port on a host. Returns (port, is_open, service_name, banner)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))

        if result == 0:
            # Port is open — try to grab banner
            banner = ''
            try:
                sock.settimeout(1.5)
                # Some services send a banner on connect
                data = sock.recv(1024)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()[:200]
            except socket.timeout:
                # No banner received — try sending a probe
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()[:200]
                except:
                    pass
            except:
                pass

            sock.close()
            service_name = COMMON_PORTS.get(port, ('Unknown', 'Unknown service'))[0]
            return port, True, service_name, banner

        sock.close()
        return port, False, None, None
    except Exception:
        return port, False, None, None


def scan_target(target, ports=None, timeout=1.0, max_workers=100):
    """
    Scan a target for open ports.
    Returns a complete scan report dictionary.
    """
    # Validate target
    valid, resolved = is_valid_target(target)
    if not valid:
        return {'error': f'Cannot resolve target: {target}'}

    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {'error': f'Cannot resolve hostname: {target}'}

    # Default: scan all common ports
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    # Run concurrent port scan
    open_ports = []
    closed_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, service, banner = future.result()
            if is_open:
                risk_level = get_port_risk(port)
                vuln_desc = VULNERABILITY_INDICATORS.get(port, '')
                open_ports.append({
                    'port': port,
                    'service': service,
                    'banner': banner[:200] if banner else '',
                    'risk_level': risk_level,
                    'vulnerability': vuln_desc
                })
            else:
                closed_count += 1

    # Sort by port number
    open_ports.sort(key=lambda x: x['port'])

    # Calculate overall risk
    risk_score = calculate_scan_risk(open_ports)

    # Generate report
    report = {
        'target': target,
        'resolved_ip': ip,
        'timestamp': datetime.now().isoformat(),
        'ports_scanned': len(ports),
        'ports_open': len(open_ports),
        'ports_closed': closed_count,
        'open_ports': open_ports,
        'risk_score': risk_score,
        'risk_level': get_risk_level(risk_score),
        'summary': generate_summary(open_ports, risk_score)
    }

    return report


def get_port_risk(port):
    """Determine risk level for a specific port."""
    if port in HIGH_RISK_PORTS:
        return 'HIGH'
    elif port in MEDIUM_RISK_PORTS:
        return 'MEDIUM'
    elif port in LOW_RISK_PORTS:
        return 'LOW'
    else:
        return 'INFO'


def calculate_scan_risk(open_ports):
    """Calculate overall risk score based on open ports."""
    score = 0
    for p in open_ports:
        if p['risk_level'] == 'HIGH':
            score += 20
        elif p['risk_level'] == 'MEDIUM':
            score += 10
        elif p['risk_level'] == 'LOW':
            score += 2
        else:
            score += 3

    # Bonus risk for multiple high-risk ports
    high_count = sum(1 for p in open_ports if p['risk_level'] == 'HIGH')
    if high_count >= 3:
        score += 15
    if high_count >= 5:
        score += 15

    return min(100, score)


def get_risk_level(score):
    """Convert risk score to risk level."""
    if score >= 75:
        return 'CRITICAL'
    elif score >= 50:
        return 'HIGH'
    elif score >= 25:
        return 'MEDIUM'
    elif score >= 10:
        return 'LOW'
    else:
        return 'MINIMAL'


def generate_summary(open_ports, risk_score):
    """Generate a text summary of the scan results."""
    if not open_ports:
        return 'No open ports detected. The target appears to have no exposed services. This is the most secure configuration.'

    high_risk = [p for p in open_ports if p['risk_level'] == 'HIGH']
    medium_risk = [p for p in open_ports if p['risk_level'] == 'MEDIUM']

    summary_parts = []
    summary_parts.append(f'{len(open_ports)} open port(s) detected on {len(open_ports)} service(s).')

    if high_risk:
        summary_parts.append(f'{len(high_risk)} HIGH RISK port(s) found: ' + ', '.join(str(p['port']) for p in high_risk))
    if medium_risk:
        summary_parts.append(f'{len(medium_risk)} MEDIUM RISK port(s) found: ' + ', '.join(str(p['port']) for p in medium_risk))

    if risk_score >= 75:
        summary_parts.append('CRITICAL: This system has significant security exposure. Immediate remediation recommended.')
    elif risk_score >= 50:
        summary_parts.append('HIGH RISK: Multiple vulnerable services detected. Review and secure exposed ports.')
    elif risk_score >= 25:
        summary_parts.append('MEDIUM RISK: Some services may need securing. Review exposed ports.')
    else:
        summary_parts.append('LOW RISK: Minimal exposure detected. Standard hardening recommended.')

    return ' '.join(summary_parts)
