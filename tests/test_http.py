"""Offline tests of the public-only HTTPS transport using real HTTP parsing."""

import gzip
import io
import socket
import ssl
import unittest
from unittest.mock import patch

import requests

from checkdmarc._http import MAX_HTTP_REDIRECTS, PublicHTTPSAdapter
from checkdmarc.bimi import parse_bimi_record


def _wire_response(body=b"ok", *, status=200, headers=()):
    lines = [f"HTTP/1.1 {status} response", "Connection: close"]
    lines += [f"{name}: {value}" for name, value in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def _addresses(hostname, port, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]


class _Socket:
    def __init__(self, response):
        self.response = response
        self.sent = bytearray()
        self.destination = None
        self.hostname = None
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, destination):
        self.destination = destination

    def sendall(self, data):
        self.sent.extend(data)

    def makefile(self, *args, **kwargs):
        return io.BytesIO(self.response)

    def close(self):
        self.closed = True


class _TLSContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True

    def set_alpn_protocols(self, protocols):
        pass

    def wrap_socket(self, sock, *, server_hostname):
        sock.hostname = server_hostname
        return sock


class TestPublicHTTPS(unittest.TestCase):
    def setUp(self):
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.max_redirects = MAX_HTTP_REDIRECTS
        adapter = PublicHTTPSAdapter(max_bytes=64)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.addCleanup(self.session.close)

    def testNonPublicAndMixedAddressesAreRejected(self):
        for address in (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.2.1",
            "192.0.0.8",
            "192.88.99.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "2001:100::1",
            "3fff::1",
        ):
            with self.subTest(address=address):
                answers = _addresses("logo.example", 443)
                answers.append(
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
                )
                with (
                    patch("checkdmarc._http.socket.getaddrinfo", return_value=answers),
                    self.assertRaisesRegex(requests.RequestException, "non-public"),
                ):
                    self.session.get("https://logo.example/logo.svg", timeout=1)

    def testDirectPrivateIPIsRejected(self):
        # Numeric literals resolve locally; no DNS or socket is contacted.
        with self.assertRaisesRegex(requests.RequestException, "non-public"):
            self.session.get("https://127.0.0.1:8443/logo.svg", timeout=1)

    def testZeroPortIsRejected(self):
        result = parse_bimi_record("v=BIMI1; l=https://logo.example:0/logo.svg")
        self.assertIn("port must be", result["image"]["error"])

    def testPinnedAddressPreservesHTTPHostAndTLSName(self):
        sock = _Socket(_wire_response())
        answers = [
            _addresses("logo.example", 8443),
            [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8443))],
        ]
        with (
            patch("checkdmarc._http.socket.getaddrinfo", side_effect=answers),
            patch("checkdmarc._http.socket.socket", return_value=sock),
            patch(
                "checkdmarc._http.ssl.create_default_context",
                return_value=_TLSContext(),
            ),
        ):
            result = self.session.get("https://logo.example:8443/a.svg?x=1", timeout=1)
        self.assertEqual(result.content, b"ok")
        self.assertEqual(sock.destination, ("8.8.8.8", 8443))
        self.assertEqual(sock.hostname, "logo.example")
        self.assertIn(b"Host: logo.example:8443\r\n", sock.sent)
        self.assertIn(b"GET /a.svg?x=1 HTTP/1.1\r\n", sock.sent)
        self.assertTrue(sock.closed)

    def testRedirectCannotDowngradeOrUsePrivateAddresses(self):
        for destination in (
            "http://127.0.0.1/logo.svg",
            "http://other.example/logo.svg",
            "https://127.0.0.1/logo.svg",
            "https://name:password@other.example/logo.svg",
            "https://other.example:0/logo.svg",
        ):
            with self.subTest(destination=destination):
                first = _Socket(
                    _wire_response(b"", status=302, headers=[("Location", destination)])
                )

                def lookup(hostname, port, **kwargs):
                    if hostname == "127.0.0.1":
                        return [
                            (
                                socket.AF_INET,
                                socket.SOCK_STREAM,
                                6,
                                "",
                                (hostname, port),
                            )
                        ]
                    return _addresses(hostname, port)

                with (
                    patch("checkdmarc._http.socket.getaddrinfo", side_effect=lookup),
                    patch("checkdmarc._http.socket.socket", side_effect=[first]),
                    patch(
                        "checkdmarc._http.ssl.create_default_context",
                        return_value=_TLSContext(),
                    ),
                    self.assertRaises(requests.RequestException),
                ):
                    self.session.get("https://logo.example/start", timeout=1)
                self.assertEqual(first.destination, ("8.8.8.8", 443))
                self.assertTrue(first.closed)

    def testPublicHTTPSRedirectSucceeds(self):
        first = _Socket(
            _wire_response(
                b"", status=302, headers=[("Location", "https://cdn.example/logo.svg")]
            )
        )
        second = _Socket(_wire_response(b"logo"))
        with (
            patch("checkdmarc._http.socket.getaddrinfo", side_effect=_addresses),
            patch("checkdmarc._http.socket.socket", side_effect=[first, second]),
            patch(
                "checkdmarc._http.ssl.create_default_context",
                return_value=_TLSContext(),
            ),
        ):
            result = self.session.get("https://logo.example/start", timeout=1)
        self.assertEqual(result.content, b"logo")
        self.assertEqual(result.url, "https://cdn.example/logo.svg")
        self.assertEqual(second.hostname, "cdn.example")

    def testRedirectLoopIsBounded(self):
        sockets = [
            _Socket(_wire_response(b"", status=302, headers=[("Location", "/again")]))
            for _ in range(MAX_HTTP_REDIRECTS + 1)
        ]
        with (
            patch("checkdmarc._http.socket.getaddrinfo", side_effect=_addresses),
            patch("checkdmarc._http.socket.socket", side_effect=sockets),
            patch(
                "checkdmarc._http.ssl.create_default_context",
                return_value=_TLSContext(),
            ),
            self.assertRaises(requests.TooManyRedirects),
        ):
            self.session.get("https://logo.example/start", timeout=1)
        self.assertTrue(all(sock.closed for sock in sockets))

    def testBodyAndGzipExpansionAreBounded(self):
        for body, headers in (
            (b"small", [("Content-Length", "65")]),
            (b"X" * 65, []),
            (gzip.compress(b"X" * 65), [("Content-Encoding", "gzip")]),
        ):
            with self.subTest(headers=headers):
                sock = _Socket(_wire_response(body, headers=headers))
                with (
                    patch(
                        "checkdmarc._http.socket.getaddrinfo", side_effect=_addresses
                    ),
                    patch("checkdmarc._http.socket.socket", return_value=sock),
                    patch(
                        "checkdmarc._http.ssl.create_default_context",
                        return_value=_TLSContext(),
                    ),
                    self.assertRaisesRegex(
                        requests.RequestException, "exceeds 64 bytes"
                    ),
                ):
                    self.session.get("https://logo.example/logo.svg", timeout=1)
                self.assertTrue(sock.closed)

    def testGzipBodyIsDecoded(self):
        sock = _Socket(
            _wire_response(
                gzip.compress(b"logo"), headers=[("Content-Encoding", "gzip")]
            )
        )
        with (
            patch("checkdmarc._http.socket.getaddrinfo", side_effect=_addresses),
            patch("checkdmarc._http.socket.socket", return_value=sock),
            patch(
                "checkdmarc._http.ssl.create_default_context",
                return_value=_TLSContext(),
            ),
        ):
            result = self.session.get("https://logo.example/logo.svg", timeout=1)
        self.assertEqual(result.content, b"logo")

    def testMalformedResponsesRemainDownloadErrors(self):
        responses = (
            _wire_response(headers=[("Content-Length", "invalid")]),
            b"not an HTTP status line\r\n\r\n",
            _wire_response(headers=[("Content-Encoding", "unexpected")]),
            _wire_response(b"\x1f\x8b", headers=[("Content-Encoding", "gzip")]),
            _wire_response(headers=[("X-Header", "x")] * 101),
        )
        for response in responses:
            sock = _Socket(response)
            with (
                self.subTest(response=response[:100]),
                patch("checkdmarc._http.socket.getaddrinfo", side_effect=_addresses),
                patch("checkdmarc._http.socket.socket", return_value=sock),
                patch(
                    "checkdmarc._http.ssl.create_default_context",
                    return_value=_TLSContext(),
                ),
                self.assertRaises(requests.RequestException),
            ):
                self.session.get("https://logo.example/logo.svg", timeout=1)
            self.assertTrue(sock.closed)

    def testTLSAndTimeoutFailuresRemainDownloadErrors(self):
        for error in (ssl.SSLError("invalid certificate"), TimeoutError("timed out")):
            with (
                self.subTest(error=error),
                patch("checkdmarc._http.socket.getaddrinfo", side_effect=_addresses),
                patch(
                    "checkdmarc._http._PinnedHTTPSConnection.connect", side_effect=error
                ),
                self.assertRaisesRegex(
                    requests.RequestException, str(error).strip("'")
                ),
            ):
                self.session.get("https://logo.example/logo.svg", timeout=1)

    def testBIMICheckDoesNotUseProxyOrNetrcCredentials(self):
        sock = _Socket(_wire_response(b"not an SVG"))
        with (
            patch.dict("os.environ", {"HTTPS_PROXY": "http://127.0.0.1:3128"}),
            patch(
                "requests.sessions.get_netrc_auth",
                side_effect=AssertionError("credentials accessed"),
            ),
            patch("checkdmarc._http.socket.getaddrinfo", side_effect=_addresses),
            patch("checkdmarc._http.socket.socket", return_value=sock),
            patch(
                "checkdmarc._http.ssl.create_default_context",
                return_value=_TLSContext(),
            ),
        ):
            result = parse_bimi_record("v=BIMI1; l=https://logo.example/logo.svg")
        self.assertIn("Failed to process BIMI image", result["image"]["error"])
        self.assertNotIn(b"Authorization:", sock.sent)
        self.assertEqual(sock.destination, ("8.8.8.8", 443))
