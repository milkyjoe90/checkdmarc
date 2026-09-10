"""DNSSEC tests"""

from __future__ import annotations

import logging
import time
import warnings
from collections.abc import Sequence
from dataclasses import dataclass

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import httpx
from dns.dnssectypes import DSDigest
from dns.nameserver import Nameserver
from dns.rdatatype import RdataType
from expiringdict import ExpiringDict

from checkdmarc._constants import (
    DEFAULT_DNS_TIMEOUT,
    DNSSEC_CACHE_MAX_AGE_SECONDS,
    DNSSEC_CACHE_MAX_LEN,
)
from checkdmarc.utils import (
    _cache_dns,
    _get_cached_dns,
    _nameserver_cache_key,
    _nameservers_to_resolver_input,
    get_base_domain,
    normalize_domain,
)

"""Copyright 2019-2023 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

logger = logging.getLogger(__name__)

DNSSEC_CACHE = ExpiringDict(
    max_len=DNSSEC_CACHE_MAX_LEN, max_age_seconds=DNSSEC_CACHE_MAX_AGE_SECONDS
)
DNSKEY_CACHE = ExpiringDict(
    max_len=DNSSEC_CACHE_MAX_LEN, max_age_seconds=DNSSEC_CACHE_MAX_AGE_SECONDS
)
TLSA_CACHE = ExpiringDict(
    max_len=DNSSEC_CACHE_MAX_LEN, max_age_seconds=DNSSEC_CACHE_MAX_AGE_SECONDS
)


# Current and successor IANA root KSKs, verified against
# https://data.iana.org/root-anchors/root-anchors.xml on 2026-09-10.
# Both validFrom dates have passed and neither has a validUntil date.
# Refresh these anchors with package releases when IANA announces rollovers
# (RFC 9718 sections 3.2 and 4.1.1); never learn a trust anchor from DNS.
_ROOT_DS = dns.rrset.from_text(
    ".",
    0,
    "IN",
    "DS",
    "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
)


@dataclass(frozen=True)
class _AuthenticatedKeys:
    rrset: dns.rrset.RRset
    expires_at: float


def _dnssec_cache_key(
    kind: str, domain: str, nameservers: Sequence[str | Nameserver]
) -> tuple:
    return (
        kind,
        normalize_domain(domain).rstrip("."),
        _nameserver_cache_key(nameservers),
    )


def _signature_expiration(rrset: dns.rrset.RRset, signatures: dns.rrset.RRset) -> float:
    # RFC 4035 section 5.3.3 limits authenticated cache lifetime by the
    # record/signature TTLs, original TTL, and signature expiration.
    now = time.time()
    return min(
        now + rrset.ttl,
        now + signatures.ttl,
        *(min(now + sig.original_ttl, sig.expiration) for sig in signatures),
    )


def _authenticate_zone_keys(
    zone: dns.name.Name,
    nameservers: Sequence[str | Nameserver],
    timeout: float,
    cache: ExpiringDict,
    *,
    _attempts: dict[dns.name.Name, _AuthenticatedKeys | None] | None = None,
) -> _AuthenticatedKeys | None:
    """Authenticate a zone's keys through parent signatures to the IANA root."""
    # Several DS signatures can name the same parent. Remember each attempt
    # within this validation, including failures, so an untrusted chain does
    # not trigger another whole tree walk for every signature. Never persist
    # failures: the next caller must be able to recover from transient DNS.
    if _attempts is None:
        _attempts = {}
    if zone in _attempts:
        return _attempts[zone]
    _attempts[zone] = None
    cache_key = (
        _dnssec_cache_key("authenticated-key", zone.to_text(), nameservers),
        tuple(str(ds) for ds in _ROOT_DS),
    )
    cached = _get_cached_dns(cache, cache_key)
    if isinstance(cached, _AuthenticatedKeys):
        _attempts[zone] = cached
        return cached
    keys, key_signature, response = _query_rrset(
        zone.to_text(), RdataType.DNSKEY, nameservers, timeout
    )
    if keys is None or key_signature is None or response is None:
        return None
    if response.rcode() != dns.rcode.NOERROR:
        return None
    keys_expiration = _signature_expiration(keys, key_signature)
    parent_expiration = float("inf")
    if zone == dns.name.root:
        ds_records = _ROOT_DS
    else:
        ds_records, ds_signatures, response = _query_rrset(
            zone.to_text(), RdataType.DS, nameservers, timeout
        )
        if ds_records is None or ds_signatures is None or response is None:
            return None
        if response.rcode() != dns.rcode.NOERROR:
            return None
        ds_expiration = _signature_expiration(ds_records, ds_signatures)
        authenticated_parent = False
        for signature in ds_signatures:
            # RFC 4035 section 5.2: DS is signed by the *parent* zone.
            # Strict ancestry also bounds recursion and rejects self-signed
            # DS records or cycles supplied by an untrusted resolver.
            parent = signature.signer
            if (
                parent == zone
                or not zone.is_subdomain(parent)
                or signature.labels != len(zone.labels) - 1
            ):
                continue
            parent_keys = _authenticate_zone_keys(
                parent, nameservers, timeout, cache, _attempts=_attempts
            )
            if parent_keys is None:
                continue
            try:
                dns.dnssec.validate_rrsig(
                    ds_records, signature, {parent: parent_keys.rrset}
                )
            except (
                dns.exception.ValidationFailure,
                dns.exception.UnsupportedAlgorithm,
            ):
                continue
            parent_expiration = min(parent_keys.expires_at, ds_expiration)
            authenticated_parent = True
            break
        if not authenticated_parent:
            return None
    trusted_keys = _ds_matched_keys(zone, ds_records, keys)
    if not trusted_keys:
        return None
    # A zone's DNSKEY RRset must be signed by a matching zone key, rather
    # than by a same-tag key belonging to a different name.
    valid_signatures = dns.rrset.RRset(zone, dns.rdataclass.IN, RdataType.RRSIG)
    for signature in key_signature:
        if signature.signer == zone and signature.labels == len(zone.labels) - 1:
            valid_signatures.add(signature)
    if not valid_signatures:
        return None
    try:
        dns.dnssec.validate(keys, valid_signatures, {zone: trusted_keys})
    except dns.exception.ValidationFailure:
        return None
    result = _AuthenticatedKeys(keys, min(parent_expiration, keys_expiration))
    _cache_dns(cache, cache_key, result, result.expires_at)
    _attempts[zone] = result
    return result


# Errors that mean one nameserver could not answer and the next one should be
# tried. ssl.SSLError is an OSError subclass, so DNS over TLS handshake
# failures are covered; httpx.HTTPError covers DNS over HTTPS transport
# failures (connection, proxy, and timeout errors).
_TRANSPORT_ERRORS = (dns.exception.DNSException, OSError, EOFError, httpx.HTTPError)


def _query_nameserver(
    request: dns.message.QueryMessage,
    nameserver: str | Nameserver,
    timeout: float,
) -> dns.message.Message:
    """
    Sends one DNS query to one nameserver, honoring its transport.

    A ``dns.nameserver.Nameserver`` object — such as the DNS over HTTPS and
    DNS over TLS nameservers that ``https://`` and ``tls://`` entries map to —
    is queried through its own ``query()`` method, with ``max_size=True`` so
    a plain-DNS ``Do53Nameserver`` uses TCP, matching the direct
    ``dns.query.tcp()`` call used for plain string entries. DNSSEC answers
    carry signatures that routinely overflow a UDP datagram.

    Args:
        request (dns.message.QueryMessage): The query to send
        nameserver: An IP address string or a ``dns.nameserver.Nameserver``
        timeout (float): Timeout in seconds

    Returns:
        dns.message.Message: The response
    """
    if isinstance(nameserver, Nameserver):
        return nameserver.query(
            request, timeout, source=None, source_port=0, max_size=True
        )
    return dns.query.tcp(request, str(nameserver), timeout=timeout)


def _find_record_and_signature(
    answer: Sequence[dns.rrset.RRset],
    name: dns.name.Name,
    rdatatype: RdataType,
) -> tuple[dns.rrset.RRset | None, dns.rrset.RRset | None]:
    """
    Pick the record set of the requested type out of a DNS answer, along with
    the signature that covers it

    An answer can hold more than one record set. A name that points at another
    name, for example, returns every link in that chain, and each link may sit
    in a different zone with a different signature (or no signature at all).
    Picking records out by name and type keeps a record from being paired with
    a signature that belongs to something else, or with no signature at all.

    Args:
        answer (Sequence): The answer section of a DNS response
        name (dns.name.Name): The name that was queried
        rdatatype (RdataType): The record type that was queried

    Returns:
        tuple: The matching record set and its signature, either of which is
        ``None`` when the answer does not contain it
    """
    rrset = None
    rrsig = None
    for rset in answer:
        if rset.name != name or rset.rdclass != dns.rdataclass.IN:
            continue
        if rset.rdtype == RdataType.RRSIG:
            if rset.covers == rdatatype:
                rrsig = rset
        elif rset.rdtype == rdatatype:
            rrset = rset

    return rrset, rrsig


def _query_rrset(
    domain: str,
    rdatatype: RdataType,
    nameservers: Sequence[str | Nameserver],
    timeout: float,
) -> tuple[dns.rrset.RRset | None, dns.rrset.RRset | None, dns.message.Message | None]:
    """
    Query one record type at one name, asking for DNSSEC signatures

    Nameservers are tried in order until one gives a usable answer; a
    transport failure, or a response code such as REFUSED or FORMERR that
    means the server could not answer rather than that the records are
    absent, moves on to the next entry. The raw response is returned
    alongside the record set and its signature so the caller can inspect the
    response code and flags — a SERVFAIL from a validating resolver carries
    meaning that an empty answer does not, so a SERVFAIL response is
    returned when no other nameserver gives a NOERROR or NXDOMAIN answer.

    Args:
        domain (str): The name to query
        rdatatype (RdataType): The record type to query
        nameservers (list): A list of nameservers to query
        timeout (float): Timeout in seconds

    Returns:
        tuple: The record set, the RRSIG covering it, and the raw response.
        All three are ``None`` when no nameserver answered; the first two are
        ``None`` when the response does not contain them.
    """
    request = dns.message.make_query(domain, rdatatype, want_dnssec=True)
    name = dns.name.from_text(domain)
    servfail_response = None
    for nameserver in nameservers:
        try:
            response = _query_nameserver(request, nameserver, timeout)
        except _TRANSPORT_ERRORS as e:
            logger.debug(f"{rdatatype.name} query error at {domain}: {e}")
            continue
        if response is None:
            continue
        rcode = response.rcode()
        if rcode == dns.rcode.SERVFAIL:
            # A validating resolver answers SERVFAIL for a zone that fails
            # validation, so the response means something — but another
            # configured nameserver may still hold a real answer. Keep the
            # first SERVFAIL and fall back to it after the loop.
            if servfail_response is None:
                servfail_response = response
            continue
        if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            # REFUSED, FORMERR, NOTIMP, and the like mean this nameserver
            # could not or would not answer, not that the record set is
            # absent; treat them like transport failures and move on.
            logger.debug(
                f"{rdatatype.name} query at {domain} returned "
                f"{dns.rcode.to_text(rcode)}; trying the next nameserver"
            )
            continue
        rrset, rrsig = _find_record_and_signature(response.answer, name, rdatatype)
        return rrset, rrsig, response
    if servfail_response is not None:
        return None, None, servfail_response
    return None, None, None


def _ds_matched_keys(
    zone_name: dns.name.Name,
    ds_rrset: dns.rrset.RRset,
    dnskey_rrset: dns.rrset.RRset,
) -> dns.rrset.RRset:
    """
    Find the DNSKEYs that the parent zone's DS records vouch for

    Per RFC 4035 section 5.2, a DS record authenticates a DNSKEY when a
    digest of that key, computed with the DS record's digest algorithm,
    matches the digest the DS record carries. Each key is digested with
    ``dns.dnssec.make_ds`` and compared against each DS record; keys with
    a digest algorithm this host cannot compute are skipped rather than
    treated as matches.

    Args:
        zone_name (dns.name.Name): The zone apex the records belong to
        ds_rrset (dns.rrset.RRset): The DS records from the parent zone
        dnskey_rrset (dns.rrset.RRset): The zone's DNSKEY records

    Returns:
        dns.rrset.RRset: The keys a DS record matches (empty when none do)
    """
    matched = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    for ds in ds_rrset:
        for key in dnskey_rrset:
            try:
                computed = dns.dnssec.make_ds(
                    zone_name, key, DSDigest(ds.digest_type), validating=True
                )
            except (
                # An undefined digest type number
                ValueError,
                # A digest type dnspython cannot compute (e.g. GOST)
                dns.exception.UnsupportedAlgorithm,
                # A digest type policy forbids validating with (NULL)
                dns.exception.DeniedByPolicy,
            ) as e:
                logger.debug(f"Skipping DS digest comparison for {zone_name}: {e}")
                continue
            if computed == ds:
                matched.add(key)
    return matched


def get_dnskey(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    cache: ExpiringDict | None = None,
) -> dict | None:
    """
    Get a DNSKEY RRset at the domain or its base domain

    This lookup does not authenticate the keys. Use :func:`check_dnssec`
    for a status backed by a chain of signatures to an IANA root key.

    Args:
        domain (str): The domain to check
        nameservers (list): A list of nameservers to query
        timeout (float): Timeout in seconds
        cache (ExpiringDict): A cache

    Returns:
        A DNSKEY dictionary if a DNSKEY is found
    """
    if nameservers is None:
        nameservers = dns.resolver.Resolver().nameservers
    nameservers = _nameservers_to_resolver_input(nameservers)
    if cache is None:
        cache = DNSKEY_CACHE

    domain = normalize_domain(domain)

    cache_key = _dnssec_cache_key("key", domain, nameservers)
    cached_result = _get_cached_dns(cache, cache_key)
    if isinstance(cached_result, dict):
        return cached_result

    logger.debug(f"Checking for DNSKEY records at {domain}")
    rrset, rrsig, response = _query_rrset(
        domain, RdataType.DNSKEY, nameservers, timeout
    )
    # A lookup that could not complete says nothing about whether the zone
    # is signed, so it is reported as "no key" without being cached — a
    # later call can still get a real answer.
    if response is None:
        logger.debug(f"No nameserver answered the DNSKEY query for {domain}")
        return None
    if response.rcode() == dns.rcode.SERVFAIL:
        logger.debug(
            f"The DNSKEY query for {domain} failed with SERVFAIL: "
            f"a validating resolver rejected the zone as bogus"
        )
        return None
    # An answer that holds no DNSKEY for this name means the same thing as
    # an empty answer: the name is not the apex of a signed zone. A name
    # that points at another name answers with that chain rather than with
    # a key, so check the base domain.
    if rrset is None:
        logger.debug(f"No DNSKEY records found at {domain}")
        base_domain = get_base_domain(domain)
        if domain != base_domain:
            return get_dnskey(
                base_domain,
                nameservers=nameservers,
                timeout=timeout,
                cache=cache,
            )
        return None
    key = {dns.name.from_text(domain): rrset}
    expires_at = time.time() + rrset.ttl
    if rrsig is not None:
        expires_at = min(expires_at, _signature_expiration(rrset, rrsig))
    _cache_dns(cache, cache_key, key, expires_at)
    return key


def check_dnssec(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    cache: ExpiringDict | None = None,
) -> bool:
    """
    Check that DNSSEC protects the given domain's records

    ``True`` means the domain has a signed record set whose keys were
    authenticated through parent signatures to a bundled IANA root key:

    - The parent zone publishes a DS record for the domain's zone (the
      domain itself, or an ancestor when the domain is not a zone apex)
    - The zone's DNSKEY record set contains a key whose digest matches that
      DS record (RFC 4034 section 5)
    - The signature over the DNSKEY record set verifies against a DS-matched
      key (RFC 4035 section 5)
    - For a domain below the zone apex, a record set at the domain itself
      (MX, A, AAAA, NS, TXT, or CNAME) carries a signature that verifies
      against those keys

    ``False`` covers every other outcome, and the log tells them apart: an
    unsigned zone (no DS record at the parent — including a zone that
    publishes a DNSKEY anyway, which validating resolvers treat as unsigned
    per RFC 4033 section 4.3), a broken zone whose parent publishes a DS
    record that its keys or signatures do not live up to (logged as a
    warning, because mail from such a domain is rejected by receivers that
    validate), and a lookup that could not complete (not cached).

    The resolver need not be trusted: its DS and DNSKEY answers must verify
    through the parent chain to an IANA root key. Root anchors are updated
    with package releases. This positive-answer check does not authenticate
    denial of existence or wildcard expansion, and does not distinguish unsigned,
    broken, and unavailable outcomes in its boolean result.

    Args:
        domain (str): The domain to check
        nameservers (list): A list of nameservers to query
        timeout (float): Timeout in seconds
        cache (ExpiringDict): Cache

    Returns:
        bool: DNSSEC status
    """
    if nameservers is None:
        nameservers = dns.resolver.Resolver().nameservers
    nameservers = _nameservers_to_resolver_input(nameservers)
    # get_dnskey keeps its own module-level cache; only hand it a cache the
    # caller supplied, so caller-isolated caches stay isolated.
    dnskey_cache = cache
    if cache is None:
        cache = DNSSEC_CACHE

    domain = normalize_domain(domain)

    # Find the zone the parent vouches for by walking from the domain
    # itself up through each ancestor to the base domain and using the
    # first (deepest) name with a DS record. A delegated signed zone
    # between the queried name and the base domain (for example
    # signed-child.example.com under www.signed-child.example.com) holds
    # the keys that actually sign the name's records, so jumping straight
    # to the base domain would validate against the wrong keys.
    base_domain = get_base_domain(domain)
    labels = domain.split(".")
    base_label_count = len(base_domain.split("."))
    candidates = [
        ".".join(labels[i:]) for i in range(max(1, len(labels) - base_label_count + 1))
    ]
    zone = candidates[-1]
    ds_rrset = None
    ds_response = None
    for candidate in candidates:
        logger.debug(f"Checking for DS records at {candidate}")
        ds_rrset, _, ds_response = _query_rrset(
            candidate, RdataType.DS, nameservers, timeout
        )
        if (
            ds_response is None
            or ds_response.rcode() == dns.rcode.SERVFAIL
            or ds_rrset is not None
        ):
            zone = candidate
            break
    if ds_response is None:
        logger.warning(
            f"Could not check DNSSEC for {domain}: no nameserver answered the DS query"
        )
        return False
    if ds_rrset is None:
        if ds_response.rcode() == dns.rcode.SERVFAIL:
            logger.warning(
                f"Could not check DNSSEC for {domain}: "
                f"the DS query for {zone} failed with SERVFAIL"
            )
            return False
        # A clean empty answer: the parent does not vouch for this zone, so
        # it is unsigned/insecure no matter what keys it publishes
        # (RFC 4033 section 4.3).
        key = get_dnskey(
            domain, nameservers=nameservers, timeout=timeout, cache=dnskey_cache
        )
        if key is not None:
            logger.warning(
                f"{zone} publishes a DNSKEY record, but its parent zone "
                f"publishes no DS record for it, so validating resolvers "
                f"treat the zone as unsigned (RFC 4033 section 4.3)"
            )
        else:
            logger.debug(
                f"{zone} is not signed: no DS record at its parent and no DNSKEY record"
            )
        return False

    zone_name = dns.name.from_text(zone)
    logger.debug(f"Found DS records for {zone}; checking its DNSKEY against them")
    dnskey_rrset, dnskey_rrsig, key_response = _query_rrset(
        zone, RdataType.DNSKEY, nameservers, timeout
    )
    if key_response is None:
        logger.warning(
            f"Could not check DNSSEC for {domain}: "
            f"no nameserver answered the DNSKEY query"
        )
        return False
    if key_response.rcode() == dns.rcode.SERVFAIL:
        logger.warning(
            f"DNSSEC for {zone} is broken: its parent zone publishes a DS "
            f"record, but the DNSKEY query failed with SERVFAIL — a "
            f"validating resolver rejected the zone as bogus"
        )
        return False
    if dnskey_rrset is None or dnskey_rrsig is None:
        logger.warning(
            f"DNSSEC for {zone} is broken: its parent zone publishes a DS "
            f"record, but {zone} did not answer with a signed DNSKEY "
            f"record set"
        )
        return False
    if key_response.flags & dns.flags.AD:
        logger.debug(
            f"The resolver set the AD flag on the {zone} DNSKEY answer: "
            f"it claims to have validated the answer (not used as a trust source)"
        )

    matched_keys = _ds_matched_keys(zone_name, ds_rrset, dnskey_rrset)
    if len(matched_keys) == 0:
        logger.warning(
            f"DNSSEC for {zone} is broken: no key in its DNSKEY record set "
            f"matches a DS record at its parent"
        )
        return False
    try:
        dns.dnssec.validate(dnskey_rrset, dnskey_rrsig, {zone_name: matched_keys})
    except dns.exception.ValidationFailure as e:
        logger.warning(
            f"DNSSEC for {zone} is broken: the signature over its DNSKEY "
            f"record set does not verify against the DS-matched key: {e}"
        )
        return False
    logger.debug(
        f"The {zone} DNSKEY record set matches a DS record at its parent "
        f"and its signature verifies"
    )

    authenticated_keys = _authenticate_zone_keys(zone_name, nameservers, timeout, cache)
    if authenticated_keys is None:
        logger.warning(
            f"Could not authenticate DNSSEC for {domain} to an IANA root key"
        )
        return False
    # Use the authenticated answer, rather than the independently retrieved
    # local-check answer: an untrusted resolver can change responses.
    dnskey_rrset = authenticated_keys.rrset

    if zone == domain:
        # The domain is the zone apex, and its DNSKEY record set — one of
        # the zone's own record sets — just validated against the parent's
        # DS record.
        return True

    # The domain sits below the zone apex, so DNSSEC only covers it if its
    # own records carry signatures that verify against the zone's keys.
    # The types below are the ones an email-security check can expect at
    # such a name; a name that only holds some other type (or no records
    # at all) returns False, as the docstring says — proving a signed
    # zone covers an empty name would take NSEC/NSEC3 authenticated
    # denial, which this bounded check does not implement.
    keyring = {zone_name: dnskey_rrset}
    rdatatypes = [
        dns.rdatatype.MX,
        dns.rdatatype.A,
        dns.rdatatype.AAAA,
        dns.rdatatype.NS,
        dns.rdatatype.TXT,
        dns.rdatatype.CNAME,
    ]
    for rdatatype in rdatatypes:
        rrset, rrsig, response = _query_rrset(domain, rdatatype, nameservers, timeout)
        if response is not None and response.rcode() == dns.rcode.SERVFAIL:
            logger.warning(
                f"DNSSEC for {domain} is broken: the {rdatatype.name} query "
                f"failed with SERVFAIL below the signed zone {zone} — a "
                f"validating resolver rejected the answer as bogus"
            )
            return False
        if rrset is None or rrsig is None:
            continue
        if response is None or response.rcode() != dns.rcode.NOERROR:
            continue
        # RFC 4035 section 5.3.4 requires authenticated denial proofs for
        # wildcard expansion. This positive-answer check does not verify
        # those proofs, so a wildcard signature cannot establish True.
        exact_signatures = dns.rrset.RRset(rrset.name, rrset.rdclass, RdataType.RRSIG)
        for signature in rrsig:
            if signature.labels == len(rrset.name.labels) - 1:
                exact_signatures.add(signature)
        if not exact_signatures:
            continue
        try:
            dns.dnssec.validate(rrset, exact_signatures, keyring)
        except dns.exception.ValidationFailure as e:
            logger.warning(
                f"The signature over the {rdatatype.name} record set at "
                f"{domain} does not verify against the {zone} keys: {e}"
            )
            continue
        logger.debug(f"Found a signed {rdatatype.name} record")
        return True

    logger.debug(f"{zone} is signed, but no signed records were found at {domain}")
    return False


def test_dnssec(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    cache: ExpiringDict | None = None,
) -> bool:
    """Deprecated alias for :func:`check_dnssec`"""
    warnings.warn(
        "test_dnssec() is deprecated; use check_dnssec()",
        DeprecationWarning,
        stacklevel=2,
    )
    return check_dnssec(domain, nameservers=nameservers, timeout=timeout, cache=cache)


def get_tlsa_records(
    hostname: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    port: int = 25,
    protocol: str = "tcp",
    cache: ExpiringDict | None = None,
) -> list[str]:
    """
    Return TLSA records authenticated through DNSSEC to an IANA root key

    Empty results cover absent, unavailable, or unauthenticated records.
    Wildcard answers requiring denial proofs and CNAME/DNAME aliases are
    not authenticated by this lookup. This function does not compare TLSA
    associations with a server certificate; it supplies authenticated DNS
    data for a separate certificate check (RFC 7672 section 2.1.1).

    Args:
        hostname (str): The hostname to check
        nameservers (list): A list of nameservers to query
        timeout (float): Timeout in seconds
        port (int): The port
        protocol (str): The protocol
        cache (ExpiringDict): A cache

    Returns:
        list: A list of TLSA records
    """
    if nameservers is None:
        nameservers = dns.resolver.Resolver().nameservers
    nameservers = _nameservers_to_resolver_input(nameservers)
    protocol = protocol.lower()
    if cache is None:
        cache = TLSA_CACHE

    query_hostname = f"_{port}._{protocol}.{hostname}"
    cache_key = (
        _dnssec_cache_key("TLSA", query_hostname, nameservers),
        tuple(str(ds) for ds in _ROOT_DS),
    )
    cached_results = _get_cached_dns(cache, cache_key)
    if isinstance(cached_results, list):
        return cached_results
    tlsa_records: list[str] = []
    if len(nameservers) == 0:
        raise ValueError("At least one nameserver is required")
    logger.debug(f"Checking for TLSA records at {query_hostname}")
    rrset, rrsig, response = _query_rrset(
        query_hostname, RdataType.TLSA, nameservers, timeout
    )
    if response is None:
        logger.debug(f"No nameserver answered the TLSA query for {query_hostname}")
        return tlsa_records
    if response.rcode() == dns.rcode.SERVFAIL:
        logger.debug(
            f"The TLSA query for {query_hostname} failed with SERVFAIL: "
            f"a validating resolver rejected the answer as bogus"
        )
        return tlsa_records
    if rrset is None or rrsig is None:
        return tlsa_records
    if response.rcode() != dns.rcode.NOERROR:
        return tlsa_records
    tlsa_expiration = _signature_expiration(rrset, rrsig)
    attempts: dict[dns.name.Name, _AuthenticatedKeys | None] = {}
    for signature in rrsig:
        signer = signature.signer
        # RFC 4035 section 5.3.4: a wildcard signature alone does not
        # authenticate its expansion at this name.
        if (
            not rrset.name.is_subdomain(signer)
            or signature.labels != len(rrset.name.labels) - 1
        ):
            continue
        keys = _authenticate_zone_keys(
            signer, nameservers, timeout, cache, _attempts=attempts
        )
        if keys is None:
            continue
        try:
            dns.dnssec.validate_rrsig(rrset, signature, {signer: keys.rrset})
        except (
            dns.exception.ValidationFailure,
            dns.exception.UnsupportedAlgorithm,
        ) as error:
            logger.debug(f"The TLSA records at {query_hostname} do not verify: {error}")
            continue
        tlsa_records = [str(record) for record in rrset]
        expires_at = min(keys.expires_at, tlsa_expiration)
        _cache_dns(cache, cache_key, tlsa_records, expires_at)
        return tlsa_records
    logger.debug(
        f"The TLSA records at {query_hostname} could not be authenticated to an IANA root key"
    )
    return tlsa_records
