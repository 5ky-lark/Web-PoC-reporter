"""
Port Scanner — Discovers open ports and running services on the target.
"""

import asyncio
import socket
from urllib.parse import urlparse

from scanners.base import BaseScanner, Finding, Severity

# Top ports to scan with service names
TOP_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    27017: "MongoDB", 11211: "Memcached",
}

DANGEROUS_PORTS = {
    3306: ("MySQL Database Exposed", Severity.HIGH, 7.5),
    5432: ("PostgreSQL Database Exposed", Severity.HIGH, 7.5),
    27017: ("MongoDB Database Exposed", Severity.HIGH, 7.5),
    6379: ("Redis Instance Exposed", Severity.HIGH, 7.5),
    11211: ("Memcached Exposed", Severity.HIGH, 7.5),
    1433: ("MSSQL Database Exposed", Severity.HIGH, 7.5),
    1521: ("Oracle Database Exposed", Severity.HIGH, 7.5),
    23: ("Telnet Service Exposed", Severity.MEDIUM, 6.5),
    21: ("FTP Service Exposed", Severity.MEDIUM, 5.3),
    5900: ("VNC Service Exposed", Severity.HIGH, 7.5),
    3389: ("RDP Service Exposed", Severity.MEDIUM, 6.5),
    445: ("SMB Service Exposed", Severity.MEDIUM, 6.5),
}


class PortScanner(BaseScanner):
    name = "ports"
    description = "Port Scan & Service Detection"

    async def scan(self, target_url: str) -> list[Finding]:
        findings = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname

        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            findings.append(self._make_finding(
                title="DNS Resolution Failed", severity=Severity.INFO,
                description=f"Cannot resolve hostname: {hostname}", evidence=f"Host: {hostname}",
            ))
            return findings

        open_ports = []
        tasks = [self._check_port(ip, port) for port in TOP_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for port, is_open in zip(TOP_PORTS.keys(), results):
            if is_open is True:
                open_ports.append(port)
                service = TOP_PORTS.get(port, "Unknown")

                if port in DANGEROUS_PORTS:
                    title, severity, cvss = DANGEROUS_PORTS[port]
                    findings.append(self._make_finding(
                        title=title, severity=severity, cvss_score=cvss,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-200", cwe_name="Information Exposure",
                        description=f"Port {port} ({service}) is open and accessible from the internet. This service should not be publicly exposed.",
                        evidence=f"Port {port} ({service}) - OPEN on {ip}",
                        poc_steps=[f"Run: nmap -p {port} {hostname}", f"Port {port} is open", f"Service: {service}"],
                        remediation=f"Restrict access to port {port} using firewall rules. Only allow connections from trusted IP addresses.",
                    ))

        if open_ports:
            port_list = ", ".join(f"{p}/{TOP_PORTS.get(p, '?')}" for p in sorted(open_ports))
            findings.append(self._make_finding(
                title=f"Open Ports Discovered ({len(open_ports)} ports)", severity=Severity.INFO,
                description=f"The following ports are open on {hostname}: {port_list}",
                evidence=f"IP: {ip}\nOpen ports: {port_list}",
            ))

        if not findings:
            findings.append(self._make_finding(
                title="No Notable Open Ports", severity=Severity.INFO,
                description="No commonly targeted ports were found open.",
            ))
        return findings

    async def _check_port(self, ip: str, port: int, timeout: float = 3.0) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
