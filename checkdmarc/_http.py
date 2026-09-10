"""Bounded HTTPS downloads from public addresses for untrusted DNS URLs."""

from __future__ import annotations

import gzip
import http.client
import io
import ipaddress
import socket
import ssl
import time
import zlib
from typing import Any
from urllib.parse import SplitResult, urljoin, urlsplit

import requests
from requests.adapters import BaseAdapter
from requests.structures import CaseInsensitiveDict
from requests.utils import DEFAULT_CA_BUNDLE_PATH

from checkdmarc._constants import DEFAULT_HTTP_TIMEOUT

MAX_HTTP_RESPONSE_BYTES = 1024 * 1024
MAX_HTTP_REDIRECTS = 5
# Keep these exclusions consistent on Python versions whose ipaddress data
# predates the IANA special-purpose registry corrections in Python 3.13.
_SPECIAL_IPV4 = (
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.88.99.0/24"),
)
_SPECIAL_IPV6 = (
    ipaddress.IPv6Network("2001::/23"),
    ipaddress.IPv6Network("3fff::/20"),
)


def validate_https_url(url: str) -> SplitResult:
    """Reject unsafe URL forms before Requests can normalize their ports."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("BIMI downloads require HTTPS on every hop")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("HTTPS download URLs cannot contain credentials")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("HTTPS port must be between 1 and 65535")
        return parsed
    except ValueError as error:
        raise requests.RequestException(str(error)) from error


def _public_addresses(hostname: str, port: int) -> list[tuple[int, tuple]]:
    """Resolve once and reject a host if any answer is not a public address."""
    addresses = []
    for family, _, _, _, address in socket.getaddrinfo(
        hostname, port, type=socket.SOCK_STREAM
    ):
        ip = ipaddress.ip_address(address[0])
        special = (
            any(ip in network for network in _SPECIAL_IPV4)
            if isinstance(ip, ipaddress.IPv4Address)
            else any(ip in network for network in _SPECIAL_IPV6)
        )
        # Multicast addresses can be marked global but are not public
        # unicast destinations. Reject transition addresses as well: their
        # embedded IPv4 destination may otherwise reach an internal host.
        transition = isinstance(ip, ipaddress.IPv6Address) and (
            ip.ipv4_mapped is not None
            or ip.sixtofour is not None
            or ip.teredo is not None
            or ip in ipaddress.IPv6Network("64:ff9b::/96")
            or ip in ipaddress.IPv6Network("64:ff9b:1::/48")
        )
        if (
            not ip.is_global
            or ip.is_multicast
            or ip.is_reserved
            or transition
            or special
        ):
            raise requests.RequestException(
                f"HTTPS downloads cannot use non-public address {ip} for {hostname}"
            )
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise requests.RequestException("Unsupported HTTPS address family")
        entry = (family, address)
        if entry not in addresses:
            addresses.append(entry)
    if not addresses:
        raise requests.RequestException(f"No public addresses found for {hostname}")
    return addresses[:8]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to checked numeric addresses while verifying the original host."""

    def __init__(
        self,
        hostname: str,
        port: int,
        addresses: list[tuple[int, tuple]],
        timeout: float,
    ):
        self._addresses = addresses
        # RFC 3986 section 3.2.2 permits a DNS root dot in URLs, but RFC
        # 6066 section 3 excludes it from TLS SNI. Keep the original host
        # for DNS resolution and the HTTP Host header.
        self._tls_hostname = hostname.removesuffix(".")
        self._connect_timeout = timeout
        self._tls_context = ssl.create_default_context(cafile=DEFAULT_CA_BUNDLE_PATH)
        self._tls_context.hostname_checks_common_name = False
        self._tls_context.set_alpn_protocols(["http/1.1"])
        super().__init__(hostname, port, timeout=timeout, context=self._tls_context)

    def connect(self) -> None:
        deadline = time.monotonic() + self._connect_timeout
        last_error: OSError | None = None
        for family, address in self._addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTPS connection timed out")
            sock = socket.socket(family, socket.SOCK_STREAM)
            try:
                sock.settimeout(remaining)
                # Do not resolve the hostname again after validating it.
                sock.connect(address)
                self.sock = self._tls_context.wrap_socket(
                    sock, server_hostname=self._tls_hostname
                )
                return
            except ssl.SSLError:
                sock.close()
                raise
            except OSError as error:
                sock.close()
                last_error = error
        if last_error is not None:
            raise last_error
        raise requests.RequestException("No HTTPS destination addresses")


def _decode_body(body: bytes, encoding: str, limit: int) -> bytes:
    """Bound expansion even when a server ignores Accept-Encoding: identity."""
    if encoding == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as compressed:
            decoded = compressed.read(limit + 1)
    elif encoding in ("", "identity"):
        decoded = body
    else:
        raise requests.RequestException(
            f"Unsupported HTTP Content-Encoding: {encoding}"
        )
    if len(decoded) > limit:
        raise requests.RequestException(f"HTTPS response exceeds {limit} bytes")
    return decoded


class PublicHTTPSAdapter(BaseAdapter):
    """Requests transport that enforces the access policy on every redirect."""

    def __init__(self, max_bytes: int = MAX_HTTP_RESPONSE_BYTES):
        self.max_bytes = max_bytes
        super().__init__()

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: Any = True,
        cert: Any = None,
        proxies: Any = None,
    ) -> requests.Response:
        if not request.url:
            raise requests.RequestException("Missing HTTPS URL")
        # BIMI draft section 7.5 permits HTTPS transport only. Check here,
        # not only in the TXT parser, because redirects supply new URLs.
        parsed = validate_https_url(request.url)
        assert parsed.hostname is not None
        if request.method != "GET" or verify is not True or cert or proxies:
            raise requests.RequestException(
                "Only verified direct HTTPS GET downloads are supported"
            )
        try:
            port = 443 if parsed.port is None else parsed.port
            seconds = float(timeout if timeout is not None else DEFAULT_HTTP_TIMEOUT)
            if seconds <= 0:
                raise ValueError("HTTPS timeout must be positive")
            addresses = _public_addresses(parsed.hostname, port)
        except (OSError, ValueError) as error:
            raise requests.RequestException(str(error)) from error
        connection = _PinnedHTTPSConnection(parsed.hostname, port, addresses, seconds)
        try:
            headers = dict(request.headers)
            headers["Accept-Encoding"] = "identity"
            headers["Connection"] = "close"
            connection.request("GET", request.path_url, headers=headers)
            with connection.getresponse() as incoming:
                location = incoming.getheader("Location")
                if incoming.status in (301, 302, 303, 307, 308) and location:
                    validate_https_url(urljoin(request.url, location))
                length = incoming.getheader("Content-Length")
                if length is not None and int(length) > self.max_bytes:
                    raise requests.RequestException(
                        f"HTTPS response exceeds {self.max_bytes} bytes"
                    )
                # Check the received length too: Content-Length is optional
                # and an untrusted server can lie about it.
                body = incoming.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    raise requests.RequestException(
                        f"HTTPS response exceeds {self.max_bytes} bytes"
                    )
                response = requests.Response()
                response.status_code = incoming.status
                response.reason = incoming.reason
                response.headers = CaseInsensitiveDict(incoming.getheaders())
                response.url = request.url
                response.request = request
                response._content = _decode_body(
                    body,
                    incoming.getheader("Content-Encoding", "").lower(),
                    self.max_bytes,
                )
                return response
        except (
            OSError,
            http.client.HTTPException,
            ValueError,
            EOFError,
            zlib.error,
        ) as error:
            raise requests.RequestException(str(error)) from error
        finally:
            connection.close()

    def close(self) -> None:
        """Connections are closed after each bounded response."""
