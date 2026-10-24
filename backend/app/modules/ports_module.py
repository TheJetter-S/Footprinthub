# =============================================================================
# FootprintHub — Ports & Services Reconnaissance Module
# =============================================================================
# Identifies open services via Shodan API (passive) or safe TCP port probing
# for top infrastructure, database, and administrative ports.
# =============================================================================

import asyncio
import socket
from typing import Any, Optional
import httpx

from app.config import settings
from app.modules.base import (
    BaseModule,
    FindingSeverity,
    ModuleFinding,
    ModuleMode,
    ModuleResult,
    ProgressCallback,
)

# High-priority ports to probe with risk levels
TOP_PORTS = [
    {"port": 21, "service": "FTP", "severity": FindingSeverity.MEDIUM, "msg": "Unencrypted FTP port open."},
    {"port": 22, "service": "SSH", "severity": FindingSeverity.INFO, "msg": "SSH remote access service open."},
    {"port": 23, "service": "Telnet", "severity": FindingSeverity.CRITICAL, "msg": "Cleartext Telnet port open to internet."},
    {"port": 25, "service": "SMTP", "severity": FindingSeverity.INFO, "msg": "SMTP mail service open."},
    {"port": 53, "service": "DNS", "severity": FindingSeverity.INFO, "msg": "DNS service open."},
    {"port": 80, "service": "HTTP", "severity": None, "msg": "Standard HTTP web service."},
    {"port": 110, "service": "POP3", "severity": FindingSeverity.LOW, "msg": "POP3 mail service open."},
    {"port": 143, "service": "IMAP", "severity": FindingSeverity.LOW, "msg": "IMAP mail service open."},
    {"port": 443, "service": "HTTPS", "severity": None, "msg": "Standard HTTPS web service."},
    {"port": 445, "service": "SMB", "severity": FindingSeverity.CRITICAL, "msg": "SMB file sharing service exposed directly to the internet."},
    {"port": 1433, "service": "MS-SQL", "severity": FindingSeverity.HIGH, "msg": "Microsoft SQL Server database exposed to public internet."},
    {"port": 3306, "service": "MySQL", "severity": FindingSeverity.HIGH, "msg": "MySQL database port exposed to public internet."},
    {"port": 3389, "service": "RDP", "severity": FindingSeverity.HIGH, "msg": "Remote Desktop Protocol (RDP) exposed publicly."},
    {"port": 5432, "service": "PostgreSQL", "severity": FindingSeverity.HIGH, "msg": "PostgreSQL database port exposed to public internet."},
    {"port": 6379, "service": "Redis", "severity": FindingSeverity.CRITICAL, "msg": "Redis in-memory database exposed without perimeter restriction."},
    {"port": 8080, "service": "HTTP-Alt", "severity": FindingSeverity.LOW, "msg": "Alternative HTTP port open."},
    {"port": 8443, "service": "HTTPS-Alt", "severity": FindingSeverity.LOW, "msg": "Alternative HTTPS port open."},
    {"port": 9200, "service": "Elasticsearch", "severity": FindingSeverity.CRITICAL, "msg": "Elasticsearch cluster port exposed to internet."},
    {"port": 27017, "service": "MongoDB", "severity": FindingSeverity.CRITICAL, "msg": "MongoDB NoSQL database port exposed to internet."},
]


class PortsModule(BaseModule):
    """
    Ports and Services Discovery Module.
    """

    name: str = "ports"
    description: str = "Common port discovery, Shodan integration, and database/management exposure detection"
    mode: ModuleMode = ModuleMode.PASSIVE
    timeout: int = 50

    async def run(
        self,
        target: str,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        open_ports: list[dict[str, Any]] = []

        # 1. Check Shodan API if key is available
        shodan_key = getattr(settings, "SHODAN_API_KEY", None)
        if shodan_key:
            self._progress(on_progress, 20, "Querying Shodan API...")
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(f"https://api.shodan.io/shodan/host/search?key={shodan_key}&query=hostname:{target}")
                    if resp.status_code == 200:
                        s_data = resp.json()
                        for match in s_data.get("matches", []):
                            open_ports.append({
                                "port": match.get("port"),
                                "service": match.get("product") or match.get("transport"),
                                "source": "shodan",
                                "banner": match.get("data", "")[:200],
                            })
            except Exception:
                pass

        # 2. Fast TCP Port Probe
        self._progress(on_progress, 40, "Checking connectivity for high-risk ports...")
        loop = asyncio.get_running_loop()

        def _check_port(host: str, port: int) -> bool:
            try:
                with socket.create_connection((host, port), timeout=2.5):
                    return True
            except Exception:
                return False

        async def _probe(p_def: dict):
            p = p_def["port"]
            is_open = await loop.run_in_executor(None, _check_port, target, p)
            if is_open:
                open_ports.append({
                    "port": p,
                    "service": p_def["service"],
                    "source": "tcp_probe",
                    "status": "open",
                })
                if p_def["severity"]:
                    findings.append(
                        ModuleFinding(
                            severity=p_def["severity"],
                            title=f"Sensitive Port Exposed: {p_def['service']} (Port {p})",
                            description=f"{p_def['msg']} Publicly exposing administrative or database services significantly increases attack surface.",
                            remediation=f"Block inbound access to port {p} via network firewall / security groups or require VPN.",
                        )
                    )

        tasks = [_probe(p) for p in TOP_PORTS]
        await asyncio.gather(*tasks)

        # Deduplicate open ports by port number
        unique_ports = {item["port"]: item for item in open_ports}.values()
        sorted_ports = sorted(list(unique_ports), key=lambda x: x["port"])

        self._progress(on_progress, 100, f"Identified {len(sorted_ports)} open port(s)")

        return ModuleResult(
            module_name=self.name,
            mode=self.mode,
            status="success",
            data={
                "target": target,
                "total_open": len(sorted_ports),
                "ports": sorted_ports,
            },
            findings=findings,
        )
