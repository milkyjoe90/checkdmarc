"""DNSSEC authentication and expiry using real signatures and synthetic DNS."""

import time
import unittest
from collections import Counter
from unittest.mock import patch

import dns.dnssec
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec
from expiringdict import ExpiringDict

from checkdmarc import dnssec


class SignedDNS:
    def __init__(self):
        self.records = {}
        self.keys = {}
        self.private_keys = {}
        for zone, parent in [(".", None), ("com.", "."), ("example.com.", "com.")]:
            name = dns.name.from_text(zone)
            private = ec.generate_private_key(ec.SECP256R1())
            key = dns.dnssec.make_dnskey(
                private.public_key(), "ECDSAP256SHA256", flags=257
            )
            self.keys[zone] = key
            self.private_keys[zone] = private
            key_rrset = dns.rrset.from_rdata(name, 300, key)
            self.publish(key_rrset, zone)
            ds = dns.rrset.from_rdata(
                name, 300, dns.dnssec.make_ds(name, key, "SHA256")
            )
            if parent is None:
                self.anchor = ds
            else:
                self.publish(ds, parent)
        self.tlsa = "3 1 1 " + "ab" * 32
        self.publish(
            dns.rrset.from_text(
                "_25._tcp.mail.example.com.", 300, "IN", "TLSA", self.tlsa
            ),
            "example.com.",
        )
        self.publish(
            dns.rrset.from_text("mail.example.com.", 300, "IN", "A", "192.0.2.1"),
            "example.com.",
        )

    def publish(self, rrset, signer, lifetime=300):
        signature = dns.dnssec.sign(
            rrset,
            self.private_keys[signer],
            dns.name.from_text(signer),
            self.keys[signer],
            lifetime=lifetime,
        )
        signatures = dns.rrset.from_rdata(rrset.name, rrset.ttl, signature)
        self.records[(rrset.name.to_text(), rrset.rdtype)] = (rrset, signatures)

    def query(self, request, nameserver, timeout):
        question = request.question[0]
        response = dns.message.make_response(request)
        response.answer.extend(
            self.records.get((question.name.to_text(), question.rdtype), ())
        )
        return response


class TestDNSSECTrust(unittest.TestCase):
    def setUp(self):
        self.dns = SignedDNS()
        self.cache = ExpiringDict(max_len=100, max_age_seconds=1800)
        self.servers = ["192.0.2.53"]
        anchor_patch = patch.object(dnssec, "_ROOT_DS", self.dns.anchor)
        query_patch = patch.object(
            dnssec, "_query_nameserver", side_effect=self.dns.query
        )
        anchor_patch.start()
        query_patch.start()
        self.addCleanup(anchor_patch.stop)
        self.addCleanup(query_patch.stop)

    def check(self, domain="example.com"):
        return dnssec.check_dnssec(domain, nameservers=self.servers, cache=self.cache)

    def tlsa(self):
        return dnssec.get_tlsa_records(
            "mail.example.com", nameservers=self.servers, cache=self.cache
        )

    def test_complete_chain_authenticates_apex_and_host(self):
        self.assertTrue(self.check())
        self.assertTrue(self.check("mail.example.com"))
        self.assertEqual(self.tlsa(), [self.dns.tlsa])

    def test_matching_but_unsigned_ds_is_untrusted(self):
        key = ("example.com.", dns.rdatatype.DS)
        self.dns.records[key] = self.dns.records[key][:1]
        self.assertFalse(self.check())
        self.assertEqual(self.tlsa(), [])

    def test_self_signed_ds_cannot_anchor_itself(self):
        ds, _ = self.dns.records[("example.com.", dns.rdatatype.DS)]
        self.dns.publish(ds, "example.com.")
        self.assertFalse(self.check())
        self.assertEqual(self.tlsa(), [])

    def test_ds_signed_by_unrelated_zone_is_untrusted(self):
        ds, _ = self.dns.records[("com.", dns.rdatatype.DS)]
        self.dns.publish(ds, "example.com.")
        self.assertFalse(self.check())

    def test_injected_root_does_not_replace_bundled_anchor(self):
        replacement = ec.generate_private_key(ec.SECP256R1())
        key = dns.dnssec.make_dnskey(
            replacement.public_key(), "ECDSAP256SHA256", flags=257
        )
        self.dns.keys["."] = key
        self.dns.private_keys["."] = replacement
        self.dns.publish(dns.rrset.from_rdata(dns.name.root, 300, key), ".")
        self.assertFalse(self.check())
        self.assertEqual(self.tlsa(), [])

    def test_broken_parent_signature_blocks_child(self):
        ds, signature = self.dns.records[("com.", dns.rdatatype.DS)]
        corrupted = next(iter(signature)).replace(signature=b"invalid")
        self.dns.records[("com.", dns.rdatatype.DS)] = (
            ds,
            dns.rrset.from_rdata(ds.name, 300, corrupted),
        )
        self.assertFalse(self.check())

    def test_unsigned_zone_keys_cannot_authenticate_tlsa(self):
        key = ("example.com.", dns.rdatatype.DNSKEY)
        self.dns.records[key] = self.dns.records[key][:1]
        self.assertEqual(self.tlsa(), [])

    def test_expired_signature_in_parent_chain_blocks_child(self):
        keys, _ = self.dns.records[("com.", dns.rdatatype.DNSKEY)]
        self.dns.publish(keys, "com.", lifetime=-1)
        self.assertFalse(self.check())
        self.assertEqual(self.tlsa(), [])

    def test_authentication_expires_at_parent_ttl(self):
        now = time.time()
        with patch("time.time", return_value=now) as clock:
            ds, _ = self.dns.records[("com.", dns.rdatatype.DS)]
            ds.ttl = 1
            self.dns.publish(ds, ".")
            self.assertEqual(self.tlsa(), [self.dns.tlsa])
            clock.return_value = now + 2
            self.dns.records.pop(("com.", dns.rdatatype.DS))
            self.assertEqual(self.tlsa(), [])

    def test_authentication_expires_at_parent_signature_expiration(self):
        now = int(time.time())
        with patch("time.time", return_value=now) as clock:
            keys, _ = self.dns.records[("com.", dns.rdatatype.DNSKEY)]
            self.dns.publish(keys, "com.", lifetime=1)
            self.assertEqual(self.tlsa(), [self.dns.tlsa])
            clock.return_value = now + 2
            self.assertEqual(self.tlsa(), [])

    def test_authenticated_cache_does_not_cross_resolver_views(self):
        self.assertEqual(self.tlsa(), [self.dns.tlsa])
        self.servers = ["192.0.2.54"]
        self.dns.records.pop(("com.", dns.rdatatype.DS))
        self.assertEqual(self.tlsa(), [])

    def test_legacy_positive_cache_cannot_bypass_authentication(self):
        self.cache["example.com"] = True
        self.cache["_25._tcp.mail.example.com"] = [self.dns.tlsa]
        self.dns.records.pop(("com.", dns.rdatatype.DS))
        self.assertFalse(self.check())
        self.assertEqual(self.tlsa(), [])

    def test_changed_trust_anchor_invalidates_cached_authentication(self):
        self.assertEqual(self.tlsa(), [self.dns.tlsa])
        empty = dns.rrset.RRset(dns.name.root, dns.rdataclass.IN, dns.rdatatype.DS)
        with patch.object(dnssec, "_ROOT_DS", empty):
            self.assertEqual(self.tlsa(), [])

    def test_wildcard_signature_without_denial_proof_is_not_authenticated(self):
        wildcard = dns.rrset.from_text("*.example.com.", 300, "IN", "A", "192.0.2.1")
        self.dns.publish(wildcard, "example.com.")
        _, signatures = self.dns.records[("*.example.com.", dns.rdatatype.A)]
        expanded = dns.rrset.from_text("mail.example.com.", 300, "IN", "A", "192.0.2.1")
        expanded_signatures = dns.rrset.from_rdata(expanded.name, 300, *signatures)
        self.dns.records[(expanded.name.to_text(), expanded.rdtype)] = (
            expanded,
            expanded_signatures,
        )
        # The cryptographic signature is valid, but does not prove that an
        # exact name or closer wildcard was absent (RFC 4035 section 5.3.4).
        keys, _ = self.dns.records[("example.com.", dns.rdatatype.DNSKEY)]
        dns.dnssec.validate(expanded, expanded_signatures, {keys.name: keys})
        self.assertFalse(self.check("mail.example.com"))

    def test_wildcard_tlsa_signature_does_not_authenticate_its_expansion(self):
        wildcard = dns.rrset.from_text(
            "*.example.com.", 300, "IN", "TLSA", self.dns.tlsa
        )
        self.dns.publish(wildcard, "example.com.")
        _, signatures = self.dns.records[("*.example.com.", dns.rdatatype.TLSA)]
        expanded = dns.rrset.from_text(
            "_25._tcp.mail.example.com.", 300, "IN", "TLSA", self.dns.tlsa
        )
        expanded_signatures = dns.rrset.from_rdata(expanded.name, 300, *signatures)
        self.dns.records[(expanded.name.to_text(), expanded.rdtype)] = (
            expanded,
            expanded_signatures,
        )
        keys, _ = self.dns.records[("example.com.", dns.rdatatype.DNSKEY)]
        dns.dnssec.validate(expanded, expanded_signatures, {keys.name: keys})
        self.assertEqual(self.tlsa(), [])

    def test_chain_fetch_time_does_not_extend_tlsa_ttl(self):
        now = time.time()
        with patch("time.time", return_value=now) as clock:
            tlsa, _ = self.dns.records[
                ("_25._tcp.mail.example.com.", dns.rdatatype.TLSA)
            ]
            tlsa.ttl = 1
            self.dns.publish(tlsa, "example.com.")
            original_query = self.dns.query

            def delayed_query(request, nameserver, timeout):
                if request.question[0].rdtype == dns.rdatatype.DNSKEY:
                    clock.return_value = now + 2
                return original_query(request, nameserver, timeout)

            with patch.object(dnssec, "_query_nameserver", side_effect=delayed_query):
                self.assertEqual(self.tlsa(), [self.dns.tlsa])
            self.dns.records.pop(("_25._tcp.mail.example.com.", dns.rdatatype.TLSA))
            self.assertEqual(self.tlsa(), [])

    def test_tlsa_uses_delegated_signer_below_registrable_domain(self):
        zone = "signed.example.com."
        name = dns.name.from_text(zone)
        private = ec.generate_private_key(ec.SECP256R1())
        key = dns.dnssec.make_dnskey(private.public_key(), "ECDSAP256SHA256", flags=257)
        self.dns.keys[zone] = key
        self.dns.private_keys[zone] = private
        self.dns.publish(dns.rrset.from_rdata(name, 300, key), zone)
        self.dns.publish(
            dns.rrset.from_rdata(name, 300, dns.dnssec.make_ds(name, key, "SHA256")),
            "example.com.",
        )
        self.dns.publish(
            dns.rrset.from_text(
                "_25._tcp.mail.signed.example.com.", 300, "IN", "TLSA", self.dns.tlsa
            ),
            zone,
        )
        self.assertEqual(
            dnssec.get_tlsa_records(
                "mail.signed.example.com", nameservers=self.servers, cache=self.cache
            ),
            [self.dns.tlsa],
        )

    def test_repeated_signers_do_not_repeat_failed_parent_walks(self):
        # Each delegation has two distinct signatures naming the same parent.
        # Without per-validation memoization, failed parent walks multiply at
        # every level. Also repeat the TLSA signer at the top of the walk.
        for key, (rrset, signatures) in list(self.dns.records.items()):
            if key[1] in (dns.rdatatype.DS, dns.rdatatype.TLSA):
                signature = next(iter(signatures))
                signatures.add(signature.replace(signature=b"bad signature"))
        root_key = (".", dns.rdatatype.DNSKEY)
        original_root = self.dns.records[root_key]
        self.dns.records.pop(root_key)
        queries = Counter()

        def query(request, nameserver, timeout):
            question = request.question[0]
            queries[(question.name.to_text(), question.rdtype)] += 1
            return self.dns.query(request, nameserver, timeout)

        with patch.object(dnssec, "_query_nameserver", side_effect=query):
            self.assertEqual(self.tlsa(), [])
        # Bound the observable network work, including the unavailable root.
        self.assertEqual(sum(queries.values()), 6)
        self.assertTrue(all(count == 1 for count in queries.values()))
        # Failures are remembered only for this call, not the caller's cache.
        self.dns.records[root_key] = original_root
        self.assertEqual(self.tlsa(), [self.dns.tlsa])
