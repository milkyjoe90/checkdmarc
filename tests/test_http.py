"""Offline tests of the public-only HTTPS transport using real HTTP parsing."""

import gzip
import io
import socket
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

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


def _https_test_server(directory):
    """Create a CA and server certificate that pass OpenSSL's strict checks."""
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HTTPS test CA")])
    certificates = []
    server_key = None
    for is_ca in (True, False):
        key = ca_key if is_ca else ec.generate_private_key(ec.SECP256R1())
        subject = (
            ca_name
            if is_ca
            else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "logo.example")])
        )
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), True)
            .add_extension(
                x509.KeyUsage(
                    True, False, False, False, False, is_ca, is_ca, False, False
                ),
                True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                False,
            )
        )
        if not is_ca:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("logo.example")]), False
            ).add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
            )
            server_key = key
        certificates.append(builder.sign(ca_key, hashes.SHA256()))
    ca_file, cert_file, key_file = (
        Path(directory) / name for name in ("ca.pem", "cert.pem", "key.pem")
    )
    ca_file.write_bytes(certificates[0].public_bytes(Encoding.PEM))
    cert_file.write_bytes(certificates[1].public_bytes(Encoding.PEM))
    assert server_key is not None
    key_file.write_bytes(
        server_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    return context, str(ca_file)


def _verify_in_memory(client_context, server_context, hostname):
    """Replace network transport with memory, retaining real TLS verification."""
    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_in, client_out, server_hostname=hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client_done = server_done = False
    for _ in range(20):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        server_in.write(client_out.read())
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        client_in.write(server_out.read())
        if client_done and server_done:
            return
    raise TimeoutError("In-memory HTTPS handshake did not finish")


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

    def testDNSRootDotPreservesResolutionAndVerifiesRealTLSIdentity(self):
        with tempfile.TemporaryDirectory() as directory:
            server_context, ca_file = _https_test_server(directory)
            received_names = []

            def receive_name(tls_socket, name, context):
                received_names.append(name)

            server_context.sni_callback = receive_name

            def wrap_socket(context, sock, *, server_hostname):
                _verify_in_memory(context, server_context, server_hostname)
                return sock

            for hostname in ("logo.example", "logo.example.", "wrong.example."):
                sock = _Socket(_wire_response())

                def lookup(name, port, *, expected_hostname=hostname, **kwargs):
                    # Removing the root dot before resolution would change the
                    # answer (for example, when DNS search domains are in use).
                    address = "8.8.8.8" if name == expected_hostname else "127.0.0.1"
                    return [
                        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
                    ]

                with (
                    self.subTest(hostname=hostname),
                    patch("checkdmarc._http.DEFAULT_CA_BUNDLE_PATH", ca_file),
                    patch("checkdmarc._http.socket.getaddrinfo", side_effect=lookup),
                    patch("checkdmarc._http.socket.socket", return_value=sock),
                    patch.object(ssl.SSLContext, "wrap_socket", wrap_socket),
                ):
                    url = f"https://{hostname}/logo.svg"
                    if hostname == "wrong.example.":
                        with self.assertRaises(requests.RequestException) as caught:
                            self.session.get(url, timeout=1)
                        self.assertIsInstance(
                            caught.exception.__cause__, ssl.SSLCertVerificationError
                        )
                    else:
                        result = self.session.get(url, timeout=1)
                        self.assertEqual(result.content, b"ok")
                        self.assertEqual(sock.destination, ("8.8.8.8", 443))
                        self.assertIn(f"Host: {hostname}\r\n".encode(), sock.sent)
                        self.assertEqual(received_names[-1], "logo.example")
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
