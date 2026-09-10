"""TLSA matching with real certificates and TLS handshakes entirely in memory."""

import hashlib
import smtplib
import ssl
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509.oid import NameOID

from checkdmarc import smtp
from checkdmarc._dane import _check_tlsa_certificate


def certificate(
    name, *, issuer=None, key=None, ca=False, san=None, expired=False, path_length=None
):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer_cert, issuer_key = issuer if issuer else (None, key)
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 30))
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length), critical=True
        )
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, ca, ca, False, False),
            critical=True,
        )
    )
    if san is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(value) for value in san]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256()), key


def tlsa(cert, usage=3, selector=1, matching=1):
    data = (
        cert.public_bytes(Encoding.DER)
        if selector == 0
        else cert.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
    )
    if matching == 1:
        data = hashlib.sha256(data).digest()
    elif matching == 2:
        data = hashlib.sha512(data).digest()
    return f"{usage} {selector} {matching} {data.hex()}"


class MemorySMTP:
    """Replace only SMTP transport; let OpenSSL actually verify the TLS session."""

    def __init__(self, hostname, context, chain, *, chain_api=True, starttls=True):
        self.hostname = hostname
        self.context = context
        self.chain = chain
        self.chain_api = chain_api
        self.starttls_available = starttls
        self.sock = None

    def ehlo_or_helo_if_needed(self):
        pass

    def starttls(self, *, context):
        if not self.starttls_available:
            raise smtplib.SMTPNotSupportedError("STARTTLS unavailable")
        client_in, client_out, server_in, server_out = (
            ssl.MemoryBIO() for _ in range(4)
        )
        client = context.wrap_bio(client_in, client_out, server_hostname=self.hostname)
        server = self.context.wrap_bio(server_in, server_out, server_side=True)
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
                self.sock = SimpleNamespace(getpeercert=client.getpeercert)
                if self.chain_api:
                    self.sock.get_unverified_chain = lambda: self.chain
                return
        raise TimeoutError("In-memory TLS handshake did not finish")

    def close(self):
        self.sock = None


class TestTLSACertificate(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = certificate("Test root", ca=True)
        self.leaf = certificate(
            "mail.example.com", issuer=self.root, san=["mail.example.com"]
        )
        self.peer_chain = [self.leaf[0], self.root[0]]
        self.peer_key = self.leaf[1]
        self.chain_api = True
        self.starttls = True

    def connect(self, hostname, *, port, timeout):
        if port != 25:
            raise AssertionError("A port 25 TLSA record must not check another service")
        folder = Path(self.directory.name)
        chain_file, key_file = folder / "chain.pem", folder / "key.pem"
        chain_file.write_bytes(
            b"".join(cert.public_bytes(Encoding.PEM) for cert in self.peer_chain)
        )
        key_file.write_bytes(
            self.peer_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(chain_file, key_file)
        return MemorySMTP(
            hostname,
            context,
            [cert.public_bytes(Encoding.DER) for cert in self.peer_chain],
            chain_api=self.chain_api,
            starttls=self.starttls,
        )

    def check(self, records, hostname="mail.example.com"):
        with patch("checkdmarc._dane.smtplib.SMTP", side_effect=self.connect):
            return _check_tlsa_certificate(hostname, records)

    def test_dane_ee_all_selectors_and_matching_types_allow_expired_self_signed_wrong_name(
        self,
    ):
        self_signed, key = certificate("unrelated.example", expired=True)
        self.peer_chain, self.peer_key = [self_signed], key
        for selector in (0, 1):
            for matching in (0, 1, 2):
                with self.subTest(selector=selector, matching=matching):
                    result = self.check(
                        [tlsa(self_signed, selector=selector, matching=matching)]
                    )
                    self.assertTrue(result["matched"], result)

    def test_dane_ee_wrong_certificate_is_a_mismatch(self):
        result = self.check([tlsa(self.root[0])])
        self.assertIs(result["matched"], False)

    def test_stronger_digest_prevents_fallback_to_matching_weaker_digest(self):
        result = self.check([tlsa(self.leaf[0]), tlsa(self.root[0], matching=2)])
        self.assertIs(result["matched"], False)

    def test_full_association_remains_eligible_beside_stronger_digest(self):
        result = self.check(
            [tlsa(self.leaf[0], matching=0), tlsa(self.root[0], matching=2)]
        )
        self.assertTrue(result["matched"])

    def test_malformed_stronger_digest_is_removed_before_digest_selection(self):
        result = self.check([tlsa(self.leaf[0]), "3 1 2 ab"])
        self.assertTrue(result["matched"])

    def test_key_rotation_accepts_one_matching_record_in_same_digest_group(self):
        result = self.check([tlsa(self.root[0]), tlsa(self.leaf[0])])
        self.assertTrue(result["matched"])

    def test_digest_preference_is_separate_for_each_selector(self):
        result = self.check(
            [tlsa(self.leaf[0]), tlsa(self.root[0], selector=0, matching=2)]
        )
        self.assertTrue(result["matched"])

    def test_unusable_records_and_absence_are_unassessed(self):
        for records in (
            [],
            ["not a record"],
            ["3 1 0 ab"],
            ["3 0 0 ab"],
            ["3 1 1 ab"],
            ["3 1 7 ab"],
            ["3 7 1 " + "ab" * 32],
            [tlsa(self.leaf[0], usage=0)],
            [tlsa(self.leaf[0], usage=1)],
            [tlsa(self.leaf[0], usage=255)],
        ):
            with self.subTest(records=records):
                result = self.check(records)
                self.assertIsNone(result["matched"])
                self.assertIn("No ", result["reason"])

    def test_dane_ta_all_selectors_and_matching_types_validate_real_chain(self):
        for selector in (0, 1):
            for matching in (0, 1, 2):
                with self.subTest(selector=selector, matching=matching):
                    result = self.check(
                        [
                            tlsa(
                                self.root[0],
                                usage=2,
                                selector=selector,
                                matching=matching,
                            )
                        ]
                    )
                    self.assertTrue(result["matched"], result)

    def test_full_dane_ta_works_without_peer_root_or_public_chain_api(self):
        self.peer_chain = [self.leaf[0]]
        self.chain_api = False
        result = self.check([tlsa(self.root[0], usage=2, selector=0, matching=0)])
        self.assertTrue(result["matched"], result)

    def test_intermediate_can_be_the_only_trust_anchor(self):
        intermediate = certificate("Intermediate", issuer=self.root, ca=True)
        leaf = certificate(
            "mail.example.com", issuer=intermediate, san=["mail.example.com"]
        )
        self.peer_chain, self.peer_key = [leaf[0], intermediate[0]], leaf[1]
        result = self.check([tlsa(intermediate[0], usage=2)])
        self.assertTrue(result["matched"], result)

    def test_matching_ta_appended_to_unrelated_chain_does_not_authenticate_peer(self):
        rogue_root = certificate("Rogue root", ca=True)
        rogue_leaf = certificate(
            "mail.example.com", issuer=rogue_root, san=["mail.example.com"]
        )
        self.peer_chain = [rogue_leaf[0], rogue_root[0], self.root[0]]
        self.peer_key = rogue_leaf[1]
        result = self.check([tlsa(self.root[0], usage=2)])
        self.assertIs(result["matched"], False)
        self.assertIn("validation failed", result["reason"])

    def test_dane_ta_rejects_wrong_host_name(self):
        result = self.check([tlsa(self.root[0], usage=2)], hostname="other.example.com")
        self.assertIs(result["matched"], False)

    def test_dane_ta_rejects_expired_leaf(self):
        expired = certificate("mail.example.com", issuer=self.root, expired=True)
        self.peer_chain, self.peer_key = [expired[0], self.root[0]], expired[1]
        self.assertIs(self.check([tlsa(self.root[0], usage=2)])["matched"], False)

    def test_dane_ta_uses_san_before_common_name(self):
        leaf = certificate(
            "mail.example.com", issuer=self.root, san=["wrong.example.com"]
        )
        self.peer_chain, self.peer_key = [leaf[0], self.root[0]], leaf[1]
        self.assertIs(self.check([tlsa(self.root[0], usage=2)])["matched"], False)

    def test_dane_ta_common_name_fallback_and_whole_label_wildcard(self):
        for name, expected in [
            ("mail.example.com", True),
            ("*.example.com", True),
            ("ma*.example.com", False),
        ]:
            with self.subTest(name=name):
                leaf = certificate(name, issuer=self.root)
                self.peer_chain, self.peer_key = [leaf[0], self.root[0]], leaf[1]
                self.assertEqual(
                    self.check([tlsa(self.root[0], usage=2)])["matched"], expected
                )

    def test_dane_ta_enforces_anchor_path_length_constraint(self):
        constrained = certificate("Constrained root", ca=True, path_length=0)
        intermediate = certificate("Intermediate", issuer=constrained, ca=True)
        leaf = certificate(
            "mail.example.com", issuer=intermediate, san=["mail.example.com"]
        )
        self.peer_chain, self.peer_key = (
            [leaf[0], intermediate[0], constrained[0]],
            leaf[1],
        )
        self.assertIs(
            self.check([tlsa(constrained[0], usage=2, selector=0)])["matched"], False
        )

    def test_missing_dane_ta_certificate_is_mismatch_when_chain_is_available(self):
        self.peer_chain = [self.leaf[0]]
        self.assertIs(self.check([tlsa(self.root[0], usage=2)])["matched"], False)

    def test_missing_public_chain_api_reports_unassessed(self):
        self.chain_api = False
        result = self.check([tlsa(self.root[0], usage=2)])
        self.assertIsNone(result["matched"])
        self.assertIn("Python 3.13", result["reason"])

    def test_mixed_unassessed_ta_and_mismatching_ee_is_not_false(self):
        self.chain_api = False
        result = self.check([tlsa(self.root[0], usage=2), tlsa(self.root[0], usage=3)])
        self.assertIsNone(result["matched"])

    def test_matching_ee_does_not_require_peer_chain_api(self):
        self.chain_api = False
        result = self.check([tlsa(self.root[0], usage=2), tlsa(self.leaf[0], usage=3)])
        self.assertTrue(result["matched"])

    def test_transport_failure_and_missing_starttls_are_unavailable(self):
        with patch(
            "checkdmarc._dane.smtplib.SMTP", side_effect=TimeoutError("timed out")
        ):
            result = _check_tlsa_certificate("mail.example.com", [tlsa(self.leaf[0])])
        self.assertIsNone(result["matched"])
        self.assertIn("timed out", result["reason"])
        self.starttls = False
        result = self.check([tlsa(self.leaf[0])])
        self.assertIsNone(result["matched"])
        self.assertIn("STARTTLS", result["reason"])

    def test_mx_default_is_unassessed_and_opt_in_reports_actual_match(self):
        with ExitStack() as stack:
            stack.enter_context(
                patch("checkdmarc.smtp.platform.system", return_value="Linux")
            )
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_mx_record_set",
                    return_value={
                        "hosts": [{"hostname": "mail.example.com", "preference": 10}],
                        "warnings": [],
                        "null_mx": False,
                        "record_count": 1,
                    },
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.query_dns", side_effect=dns.resolver.NoAnswer())
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_a_records", return_value=["192.0.2.1"])
            )
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_reverse_dns", return_value=["mail.example.com"]
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.check_dnssec", return_value=True)
            )
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_tlsa_records",
                    return_value=[tlsa(self.leaf[0])],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.test_starttls", return_value=True)
            )
            with patch(
                "checkdmarc._dane.smtplib.SMTP",
                side_effect=AssertionError("SMTP must be opt in"),
            ):
                result = smtp.get_mx_hosts("example.com")
            self.assertIn("tlsa_certificate", result["hosts"][0])
            unassessed = result["hosts"][0].get("tlsa_certificate")
            assert unassessed is not None
            self.assertIsNone(unassessed["matched"])
            with patch("checkdmarc._dane.smtplib.SMTP", side_effect=self.connect):
                result = smtp.get_mx_hosts("example.com", check_mx_tls=True)
            matched = result["hosts"][0].get("tlsa_certificate")
            assert matched is not None
            self.assertIs(matched["matched"], True)
            self.assertEqual(result["warnings"], [])
            with (
                patch("checkdmarc._dane.smtplib.SMTP", side_effect=self.connect),
                patch(
                    "checkdmarc.smtp.get_tlsa_records",
                    return_value=[tlsa(self.root[0])],
                ),
            ):
                result = smtp.get_mx_hosts("example.com", check_mx_tls=True)
            mismatch = result["hosts"][0].get("tlsa_certificate")
            assert mismatch is not None
            self.assertIs(mismatch["matched"], False)
            self.assertTrue(result["hosts"][0].get("starttls"))
            self.assertTrue(
                any("does not match" in warning for warning in result["warnings"])
            )

    def test_partial_ta_assessment_does_not_report_false_for_unassessed_alternative(
        self,
    ):
        self.chain_api = False
        unrelated = certificate("Unrelated root", ca=True)
        result = self.check(
            [
                tlsa(unrelated[0], usage=2, selector=0, matching=0),
                tlsa(self.root[0], usage=2, selector=0, matching=1),
            ]
        )
        self.assertIsNone(result["matched"])
        self.assertIn("other TA records", result["reason"])
