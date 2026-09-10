"""DNS answers must expire and remain isolated between resolver views."""

import unittest
from typing import cast
from unittest.mock import patch

import dns.message
import dns.name
import dns.rdataclass
import dns.resolver
import dns.rrset
from expiringdict import ExpiringDict

from checkdmarc.utils import get_mx_records, query_dns


def answer(name, record_type, ttl, value, cname_ttl=None):
    name = name.rstrip(".") + "."
    request = dns.message.make_query(name, record_type)
    response = dns.message.make_response(request)
    target = name
    if cname_ttl is not None:
        target = "target.example.net."
        response.answer.append(
            dns.rrset.from_text(name, cname_ttl, "IN", "CNAME", target)
        )
    response.answer.append(dns.rrset.from_text(target, ttl, "IN", record_type, value))
    parsed_response = cast(
        dns.message.QueryMessage, dns.message.from_wire(response.to_wire())
    )
    return dns.resolver.Answer(
        dns.name.from_text(name),
        request.question[0].rdtype,
        dns.rdataclass.IN,
        parsed_response,
    )


class TestDNSCache(unittest.TestCase):
    def setUp(self):
        self.cache = ExpiringDict(max_len=100, max_age_seconds=1800)
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = ["192.0.2.1"]

    def test_zero_ttl_is_not_reused(self):
        with patch.object(self.resolver, "resolve") as resolve:
            resolve.side_effect = [
                answer("example.com", "TXT", 0, "old"),
                answer("example.com", "TXT", 0, "new"),
            ]
            self.assertEqual(
                query_dns(
                    "example.com", "TXT", resolver=self.resolver, cache=self.cache
                ),
                ["old"],
            )
            self.assertEqual(
                query_dns(
                    "example.com", "TXT", resolver=self.resolver, cache=self.cache
                ),
                ["new"],
            )

    def test_shorter_alias_ttl_expires_the_whole_answer(self):
        with patch("time.time", return_value=1000) as clock:
            initial = answer("example.com", "TXT", 300, "old", cname_ttl=1)
            with patch.object(
                self.resolver, "resolve", return_value=initial
            ) as resolve:
                self.assertEqual(
                    query_dns(
                        "example.com", "TXT", resolver=self.resolver, cache=self.cache
                    ),
                    ["old"],
                )
                clock.return_value = 1000.5
                resolve.return_value = answer("example.com", "TXT", 300, "new")
                self.assertEqual(
                    query_dns(
                        "example.com", "TXT", resolver=self.resolver, cache=self.cache
                    ),
                    ["old"],
                )
                clock.return_value = 1001
                self.assertEqual(
                    query_dns(
                        "example.com", "TXT", resolver=self.resolver, cache=self.cache
                    ),
                    ["new"],
                )

    def test_resolver_configuration_change_uses_new_view(self):
        with patch.object(
            self.resolver,
            "resolve",
            return_value=answer("example.com", "TXT", 300, "old"),
        ) as resolve:
            self.assertEqual(
                query_dns(
                    "example.com", "TXT", resolver=self.resolver, cache=self.cache
                ),
                ["old"],
            )
            self.resolver.nameservers = ["192.0.2.2"]
            resolve.return_value = answer("example.com", "TXT", 300, "new")
            self.assertEqual(
                query_dns(
                    "example.com", "TXT", resolver=self.resolver, cache=self.cache
                ),
                ["new"],
            )

    def test_custom_resolvers_do_not_share_answers(self):
        second = dns.resolver.Resolver(configure=False)
        second.nameservers = self.resolver.nameservers
        with (
            patch.object(
                self.resolver,
                "resolve",
                return_value=answer("example.com", "TXT", 300, "first-view"),
            ),
            patch.object(
                second,
                "resolve",
                return_value=answer("example.com", "TXT", 300, "second-view"),
            ),
        ):
            self.assertEqual(
                query_dns(
                    "example.com", "TXT", resolver=self.resolver, cache=self.cache
                ),
                ["first-view"],
            )
            self.assertEqual(
                query_dns("example.com", "TXT", resolver=second, cache=self.cache),
                ["second-view"],
            )

    def test_retry_preserves_txt_format_and_caller_cache(self):
        txt = answer("example.com", "TXT", 300, '"first " "second"')
        with patch.object(
            self.resolver, "resolve", side_effect=[dns.resolver.LifetimeTimeout(), txt]
        ):
            self.assertEqual(
                query_dns(
                    "example.com",
                    "TXT",
                    resolver=self.resolver,
                    cache=self.cache,
                    quoted_txt_segments=True,
                    retries=1,
                ),
                ['"first ""second"'],
            )
        with patch.object(
            self.resolver,
            "resolve",
            side_effect=AssertionError("live lookup unavailable"),
        ):
            self.assertEqual(
                query_dns(
                    "example.com",
                    "TXT",
                    resolver=self.resolver,
                    cache=self.cache,
                    quoted_txt_segments=True,
                ),
                ['"first ""second"'],
            )

    def test_parsed_mx_obeys_ttl(self):
        with (
            patch("checkdmarc.utils.DNS_CACHE", self.cache),
            patch("time.time", return_value=1000) as clock,
            patch.object(
                self.resolver,
                "resolve",
                return_value=answer("example.com", "MX", 1, "10 old.example.com."),
            ) as resolve,
        ):
            self.assertEqual(
                get_mx_records("example.com", resolver=self.resolver)[0]["hostname"],
                "old.example.com",
            )
            clock.return_value = 1001
            resolve.return_value = answer(
                "example.com", "MX", 300, "10 new.example.com."
            )
            self.assertEqual(
                get_mx_records("example.com", resolver=self.resolver)[0]["hostname"],
                "new.example.com",
            )

    def test_parsed_mx_obeys_resolver_context(self):
        with (
            patch("checkdmarc.utils.DNS_CACHE", self.cache),
            patch.object(
                self.resolver,
                "resolve",
                return_value=answer("example.com", "MX", 300, "10 old.example.com."),
            ) as resolve,
        ):
            self.assertEqual(
                get_mx_records("example.com", resolver=self.resolver)[0]["hostname"],
                "old.example.com",
            )
            self.resolver.nameservers = ["192.0.2.2"]
            resolve.return_value = answer(
                "example.com", "MX", 300, "10 new.example.com."
            )
            self.assertEqual(
                get_mx_records("example.com", resolver=self.resolver)[0]["hostname"],
                "new.example.com",
            )
