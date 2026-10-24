# =============================================================================
# FootprintHub — SSRF Guard Tests
# =============================================================================
# Tests that explicitly verify SSRF protection blocks private/reserved IPs,
# localhost, metadata endpoints, and passes valid public domains.
# =============================================================================

import pytest
from app.core.ssrf_guard import (
    is_ip_blocked,
    is_hostname_blocked,
    validate_domain,
    validate_url,
    SSRFError,
)


class TestIPBlocking:
    """Test that private and reserved IP ranges are blocked."""

    @pytest.mark.parametrize("ip", [
        "127.0.0.1",
        "127.0.0.2",
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.1.100",
        "169.254.169.254",  # Cloud metadata
        "0.0.0.0",
    ])
    def test_blocked_ipv4(self, ip):
        assert is_ip_blocked(ip) is True

    @pytest.mark.parametrize("ip", [
        "::1",
        "fe80::1",
        "fc00::1",
        "fd00::1",
    ])
    def test_blocked_ipv6(self, ip):
        assert is_ip_blocked(ip) is True

    @pytest.mark.parametrize("ip", [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",  # example.com
        "142.250.185.14",  # google.com
    ])
    def test_allowed_public_ips(self, ip):
        assert is_ip_blocked(ip) is False


class TestHostnameBlocking:
    """Test that localhost and metadata hostnames are blocked."""

    @pytest.mark.parametrize("hostname", [
        "localhost",
        "localhost.localdomain",
        "169.254.169.254",
        "metadata.google.internal",
    ])
    def test_blocked_hostnames(self, hostname):
        assert is_hostname_blocked(hostname) is True

    def test_allowed_hostnames(self):
        assert is_hostname_blocked("example.com") is False
        assert is_hostname_blocked("google.com") is False


class TestDomainValidation:
    """Test domain validation and sanitization."""

    def test_valid_domain(self):
        assert validate_domain("example.com") == "example.com"

    def test_strips_protocol(self):
        assert validate_domain("https://example.com") == "example.com"
        assert validate_domain("http://example.com") == "example.com"

    def test_strips_path(self):
        assert validate_domain("example.com/path?q=1") == "example.com"

    def test_preserves_subdomain(self):
        assert validate_domain("sub.example.com") == "sub.example.com"

    def test_rejects_localhost(self):
        with pytest.raises(SSRFError):
            validate_domain("localhost")

    def test_rejects_empty(self):
        with pytest.raises(SSRFError):
            validate_domain("")

    def test_rejects_private_ip(self):
        with pytest.raises(SSRFError):
            validate_domain("192.168.1.1")


class TestURLValidation:
    """Test full URL validation."""

    def test_valid_https_url(self):
        assert validate_url("https://example.com") == "https://example.com"

    def test_rejects_ftp_scheme(self):
        with pytest.raises(SSRFError):
            validate_url("ftp://example.com")

    def test_rejects_file_scheme(self):
        with pytest.raises(SSRFError):
            validate_url("file:///etc/passwd")

    def test_rejects_localhost_url(self):
        with pytest.raises(SSRFError):
            validate_url("http://localhost:8080")

    def test_rejects_metadata_url(self):
        with pytest.raises(SSRFError):
            validate_url("http://169.254.169.254/latest/meta-data/")
