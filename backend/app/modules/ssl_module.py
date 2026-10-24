# =============================================================================
# FootprintHub — SSL/TLS Reconnaissance Module
# =============================================================================
# Analyzes TLS certificates (validity, issuer, SANs), protocol versions
# (TLS 1.0, 1.1, 1.2, 1.3), self-signed certificates, and cipher suite hygiene.
# =============================================================================

import asyncio
from datetime import datetime, timezone
import socket
import ssl
from typing import Any, Optional

from app.modules.base import (
    BaseModule,
    FindingSeverity,
    ModuleFinding,
    ModuleMode,
    ModuleResult,
    ProgressCallback,
)


class SSLModule(BaseModule):
    """
    SSL/TLS Certificate and Protocol Reconnaissance Module.
    """

    name: str = "ssl_tls"
    description: str = "Certificate inspection, expiration, SANs, TLS 1.0-1.3 protocol validation"
    mode: ModuleMode = ModuleMode.PASSIVE
    timeout: int = 40

    async def run(
        self,
        target: str,
        on_progress: Optional[ProgressCallback] = None,
    ) -> ModuleResult:
        findings: list[ModuleFinding] = []
        data: dict[str, Any] = {
            "target": target,
            "port": 443,
            "certificate": None,
            "protocols": {},
            "cipher": None,
        }

        self._progress(on_progress, 20, "Establishing TLS connection to port 443...")
        cert_info = await self._get_certificate_info(target, findings)
        data["certificate"] = cert_info

        if not cert_info:
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.HIGH,
                    title="No SSL/TLS Service Available (Port 443)",
                    description=f"Could not complete a TLS handshake with {target}:443.",
                    remediation="Deploy and configure an active SSL/TLS certificate for all web properties.",
                )
            )
            return ModuleResult(
                module_name=self.name,
                mode=self.mode,
                status="success",
                data=data,
                findings=findings,
            )

        self._progress(on_progress, 60, "Testing supported TLS protocol versions (1.0 - 1.3)...")
        protocols_supported = await self._test_tls_protocols(target, findings)
        data["protocols"] = protocols_supported

        self._progress(on_progress, 100, "SSL/TLS analysis completed")

        return ModuleResult(
            module_name=self.name,
            mode=self.mode,
            status="success",
            data=data,
            findings=findings,
        )

    async def _get_certificate_info(
        self,
        hostname: str,
        findings: list[ModuleFinding],
    ) -> Optional[dict[str, Any]]:
        """Fetch and parse peer certificate information."""
        def _fetch():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # Fetch cert even if untrusted/expired to inspect it

            with socket.create_connection((hostname, 443), timeout=6.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return cert_dict, cert_bin, cipher, version

        loop = asyncio.get_running_loop()
        try:
            cert_dict, cert_bin, cipher, version = await loop.run_in_executor(None, _fetch)
        except Exception:
            return None

        # Parse subject and issuer
        subject = dict(x[0] for x in cert_dict.get("subject", []))
        issuer = dict(x[0] for x in cert_dict.get("issuer", []))
        sans = [val for key, val in cert_dict.get("subjectAltName", []) if key == "DNS"]

        # Parse dates
        not_before_str = cert_dict.get("notBefore")
        not_after_str = cert_dict.get("notAfter")
        days_left = None

        if not_after_str:
            try:
                # SSL date format: 'May 10 12:00:00 2026 GMT'
                exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (exp_date - now).days

                if days_left < 0:
                    findings.append(
                        ModuleFinding(
                            severity=FindingSeverity.CRITICAL,
                            title="SSL/TLS Certificate Expired",
                            description=f"The certificate for {hostname} expired {abs(days_left)} day(s) ago on {not_after_str}.",
                            remediation="Renew and install an updated SSL/TLS certificate immediately.",
                        )
                    )
                elif days_left <= 30:
                    findings.append(
                        ModuleFinding(
                            severity=FindingSeverity.HIGH,
                            title=f"Certificate Expiring Soon ({days_left} days left)",
                            description=f"The certificate will expire on {not_after_str}.",
                            remediation="Trigger certificate renewal to avoid service disruption.",
                        )
                    )
            except Exception:
                pass

        # Check self-signed
        is_self_signed = subject.get("commonName") == issuer.get("commonName") and subject.get("organizationName") == issuer.get("organizationName")
        if is_self_signed:
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.HIGH,
                    title="Self-Signed SSL/TLS Certificate Detected",
                    description=f"The certificate for {hostname} is self-signed and not issued by a recognized Certificate Authority.",
                    remediation="Replace self-signed certificate with one issued by a trusted public CA (e.g. Let's Encrypt).",
                )
            )

        # Check SAN match
        domain_matched = False
        target_lower = hostname.lower()
        for san in sans:
            san_lower = san.lower()
            if san_lower == target_lower:
                domain_matched = True
                break
            if san_lower.startswith("*.") and target_lower.endswith(san_lower[2:]):
                domain_matched = True
                break

        if not domain_matched and sans:
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.HIGH,
                    title="Hostname Mismatch in Certificate SANs",
                    description=f"Requested hostname {hostname} is not covered in Subject Alternative Names list: {sans[:5]}.",
                    remediation="Reissue certificate including {hostname} in the SAN field.",
                )
            )

        return {
            "subject": subject,
            "issuer": issuer,
            "subject_alt_names": sans,
            "valid_from": not_before_str,
            "valid_to": not_after_str,
            "days_until_expiration": days_left,
            "is_self_signed": is_self_signed,
            "cipher_suite": cipher,
            "active_version": version,
        }

    async def _test_tls_protocols(
        self,
        hostname: str,
        findings: list[ModuleFinding],
    ) -> dict[str, bool]:
        """Check availability of each TLS protocol version."""
        protocols = {}

        # TLS versions to probe
        test_matrix = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1, FindingSeverity.HIGH, "Deprecated TLS 1.0 Protocol Enabled", "Disable TLS 1.0 on web server and load balancer configurations."),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, FindingSeverity.MEDIUM, "Deprecated TLS 1.1 Protocol Enabled", "Disable TLS 1.1 across all listening TLS services."),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2, None, None, None),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3, None, None, None),
        ]

        loop = asyncio.get_running_loop()

        def _probe_version(version_enum):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version_enum
                ctx.maximum_version = version_enum
                with socket.create_connection((hostname, 443), timeout=4.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        return True
            except Exception:
                return False

        for name, ver_enum, sev, title, remediation in test_matrix:
            supported = await loop.run_in_executor(None, _probe_version, ver_enum)
            protocols[name] = supported
            if supported and sev:
                findings.append(
                    ModuleFinding(
                        severity=sev,
                        title=title,
                        description=f"{hostname} supports {name}, which contains known cryptographic weaknesses and fails modern compliance standards (PCI-DSS).",
                        remediation=remediation,
                    )
                )

        if not protocols.get("TLSv1.3", False) and protocols.get("TLSv1.2", False):
            findings.append(
                ModuleFinding(
                    severity=FindingSeverity.INFO,
                    title="TLS 1.3 Not Enabled",
                    description=f"{hostname} supports TLS 1.2 but does not have TLS 1.3 enabled.",
                    remediation="Enable TLS 1.3 for enhanced security and 0-RTT connection speed.",
                )
            )

        return protocols
