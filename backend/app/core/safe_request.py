# =============================================================================
# FootprintHub — Safe HTTP Request Client
# =============================================================================
# Wraps httpx with SSRF protection, timeouts, response-size limits,
# and a custom User-Agent. All outbound HTTP requests in modules MUST
# use this client instead of raw httpx.
# =============================================================================

from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.core.ssrf_guard import (
    SSRFError,
    is_ip_blocked,
    resolve_and_validate,
    validate_url,
)

# Identify ourselves honestly in all outbound requests
USER_AGENT = "FootprintHub/1.0 (Authorized Security Assessment Tool)"


class SSRFSafeTransport(httpx.AsyncHTTPTransport):
    """
    Custom httpx transport that validates every resolved IP before connecting,
    preventing DNS rebinding and redirect-based SSRF attacks.
    """

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Re-validate the host IP before each request (including redirects)
        hostname = request.url.host
        if hostname:
            try:
                resolve_and_validate(hostname)
            except SSRFError:
                raise SSRFError(
                    f"Redirect to blocked host detected: {hostname}"
                )
        return await super().handle_async_request(request)


async def safe_get(
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    params: Optional[dict[str, Any]] = None,
    timeout: float = 30.0,
    max_size: Optional[int] = None,
    follow_redirects: bool = True,
) -> httpx.Response:
    """
    Make a safe GET request with SSRF protection.

    Args:
        url: Target URL (validated before request).
        headers: Additional headers to send.
        params: Query parameters.
        timeout: Request timeout in seconds.
        max_size: Max response body size in bytes (default from settings).
        follow_redirects: Whether to follow HTTP redirects.

    Returns:
        httpx.Response

    Raises:
        SSRFError: If the target is a blocked/private address.
        httpx.TimeoutException: If the request times out.
    """
    # Step 1: Validate URL scheme and hostname
    validate_url(url)

    # Step 2: Pre-resolve and validate all IPs
    parsed = urlparse(url)
    if parsed.hostname:
        resolve_and_validate(parsed.hostname)

    # Step 3: Build safe client with SSRF transport
    max_size = max_size or settings.MAX_RESPONSE_SIZE_BYTES
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)

    transport = SSRFSafeTransport()
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout),
        follow_redirects=follow_redirects,
        max_redirects=5,
    ) as client:
        response = await client.get(url, headers=request_headers, params=params)

        # Step 4: Enforce response size limit
        content_length = response.headers.get("content-length")
        if content_length and int(content_length) > max_size:
            raise SSRFError(
                f"Response too large: {content_length} bytes (limit: {max_size})"
            )

        return response


async def safe_head(
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    timeout: float = 15.0,
    follow_redirects: bool = True,
) -> httpx.Response:
    """Make a safe HEAD request with SSRF protection."""
    validate_url(url)
    parsed = urlparse(url)
    if parsed.hostname:
        resolve_and_validate(parsed.hostname)

    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)

    transport = SSRFSafeTransport()
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout),
        follow_redirects=follow_redirects,
        max_redirects=5,
    ) as client:
        return await client.head(url, headers=request_headers)


async def safe_request(
    method: str,
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    params: Optional[dict[str, Any]] = None,
    json: Optional[dict[str, Any]] = None,
    timeout: float = 30.0,
    max_size: Optional[int] = None,
    follow_redirects: bool = True,
) -> httpx.Response:
    """
    General-purpose safe HTTP request with SSRF protection.
    Supports GET, POST, HEAD, etc.
    """
    validate_url(url)
    parsed = urlparse(url)
    if parsed.hostname:
        resolve_and_validate(parsed.hostname)

    max_size = max_size or settings.MAX_RESPONSE_SIZE_BYTES
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)

    transport = SSRFSafeTransport()
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout),
        follow_redirects=follow_redirects,
        max_redirects=5,
    ) as client:
        response = await client.request(
            method, url, headers=request_headers, params=params, json=json
        )

        if method.upper() != "HEAD":
            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > max_size:
                raise SSRFError(
                    f"Response too large: {content_length} bytes (limit: {max_size})"
                )

        return response
