# =============================================================================
# FootprintHub — SSRF Protection Guard
# =============================================================================
# Defense-in-depth: validates hostnames and IPs against private/reserved ranges
# BEFORE making any outbound request, and RE-VALIDATES after DNS resolution
# and after following redirects.
# =============================================================================

import ipaddress
import socket
from urllib.parse import urlparse
from typing import Optional

# ── Blocked IP Networks (RFC 1918, loopback, link-local, etc.) ──────────────
BLOCKED_NETWORKS = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("10.0.0.0/8"),          # Private
    ipaddress.ip_network("100.64.0.0/10"),       # Shared (CGNAT)
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local
    ipaddress.ip_network("172.16.0.0/12"),       # Private
    ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol
    ipaddress.ip_network("192.0.2.0/24"),        # Documentation
    ipaddress.ip_network("192.88.99.0/24"),      # 6to4 relay
    ipaddress.ip_network("192.168.0.0/16"),      # Private
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),     # Documentation
    ipaddress.ip_network("203.0.113.0/24"),      # Documentation
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("::/128"),              # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),       # IPv4-mapped
    ipaddress.ip_network("64:ff9b::/96"),        # NAT64
    ipaddress.ip_network("100::/64"),            # Discard
    ipaddress.ip_network("fc00::/7"),            # Unique local
    ipaddress.ip_network("fe80::/10"),           # Link-local
    ipaddress.ip_network("ff00::/8"),            # Multicast
]

# ── Blocked hostnames ───────────────────────────────────────────────────────
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",       # GCP metadata
    "instance-data",                  # Cloud metadata
    "169.254.169.254",                # AWS/GCP/Azure metadata
}


class SSRFError(Exception):
    """Raised when a request is blocked by the SSRF guard."""
    pass


def is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address falls within any blocked network range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # Invalid IP → block by default

    for network in BLOCKED_NETWORKS:
        if ip in network:
            return True
    return False


def is_hostname_blocked(hostname: str) -> bool:
    """Check if a hostname is in the blocked list."""
    hostname_lower = hostname.lower().strip(".")
    if hostname_lower in BLOCKED_HOSTNAMES:
        return True
    # Also block raw IP addresses that resolve to private ranges
    try:
        ip = ipaddress.ip_address(hostname_lower)
        return is_ip_blocked(str(ip))
    except ValueError:
        pass  # Not an IP literal — continue
    return False


def validate_domain(domain: str) -> str:
    """
    Validate and sanitize a domain name.
    Returns the cleaned domain or raises SSRFError.
    """
    # Strip whitespace and protocol prefixes
    domain = domain.strip().lower()
    for prefix in ("http://", "https://", "ftp://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    # Remove trailing slashes and paths
    domain = domain.split("/")[0].split("?")[0].split("#")[0]

    if not domain:
        raise SSRFError("Empty domain")

    # Check hostname blocklist
    if is_hostname_blocked(domain):
        raise SSRFError(f"Domain '{domain}' is blocked (private/reserved)")

    # Extract and validate using tldextract with regex fallback
    try:
        import tldextract
        extracted = tldextract.extract(domain)
        if not extracted.domain or not extracted.suffix:
            raise SSRFError(f"Invalid domain: '{domain}' — no valid TLD found")
        if extracted.subdomain:
            clean = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
        else:
            clean = f"{extracted.domain}.{extracted.suffix}"
        return clean
    except ImportError:
        import re
        pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
        if not re.match(pattern, domain):
            raise SSRFError(f"Invalid domain format: '{domain}'")
        return domain


def validate_url(url: str) -> str:
    """
    Validate a full URL for SSRF safety.
    Returns the cleaned URL or raises SSRFError.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFError(f"Blocked scheme: {parsed.scheme}")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("No hostname in URL")

    if is_hostname_blocked(hostname):
        raise SSRFError(f"Blocked hostname: {hostname}")

    return url


def validate_resolved_ip(ip_str: str, original_target: str = "") -> None:
    """
    Re-validate an IP AFTER DNS resolution or redirect.
    Called by safe_request.py to catch DNS rebinding and redirect attacks.
    """
    if is_ip_blocked(ip_str):
        raise SSRFError(
            f"DNS resolution for '{original_target}' returned blocked IP: {ip_str}"
        )


def resolve_and_validate(hostname: str) -> list[str]:
    """
    Resolve a hostname to IPs and validate each one.
    Returns list of safe IPs or raises SSRFError.
    """
    if is_hostname_blocked(hostname):
        raise SSRFError(f"Blocked hostname: {hostname}")

    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        raise SSRFError(f"DNS resolution failed for: {hostname}")

    ips = list({info[4][0] for info in infos})
    if not ips:
        raise SSRFError(f"No IPs resolved for: {hostname}")

    for ip in ips:
        if is_ip_blocked(ip):
            raise SSRFError(
                f"DNS resolution for '{hostname}' returned blocked IP: {ip}"
            )

    return ips
