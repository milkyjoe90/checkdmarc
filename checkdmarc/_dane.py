"""Match an SMTP server certificate against already authenticated TLSA data."""

from __future__ import annotations

import hashlib
import smtplib
import ssl
from typing import cast

import dns.exception
import dns.rdata
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)
from dns.rdtypes.ANY.TLSA import TLSA

from checkdmarc._constants import DEFAULT_SMTP_TIMEOUT
from checkdmarc.utils import TLSACertificateResult, normalize_domain


def _usable_records(records: list[str]) -> list[TLSA]:
    usable = []
    for text in records:
        try:
            record = cast(TLSA, dns.rdata.from_text("IN", "TLSA", text))
            # RFC 6698 section 4.1 and RFC 7672 section 3.1.3: unknown
            # parameters, malformed associations, and PKIX usages are unusable.
            if (
                record.usage not in (2, 3)
                or record.selector not in (0, 1)
                or record.mtype not in (0, 1, 2)
            ):
                continue
            if record.mtype == 1 and len(record.cert) != 32:
                continue
            if record.mtype == 2 and len(record.cert) != 64:
                continue
            if record.mtype == 0:
                if record.selector == 0:
                    x509.load_der_x509_certificate(record.cert)
                else:
                    load_der_public_key(record.cert)
            usable.append(record)
        except (dns.exception.DNSException, ValueError, UnsupportedAlgorithm):
            continue
    # RFC 7671 section 9, required by RFC 7672 section 5: choose the
    # strongest supported digest separately for each usage and selector.
    # Full(0) records always remain usable, including during key rollover.
    strongest: dict[tuple[int, int], int] = {}
    for record in usable:
        group = (record.usage, record.selector)
        strongest[group] = max(strongest.get(group, 0), record.mtype)
    return [
        record
        for record in usable
        if record.mtype == 0
        or record.mtype == strongest[(record.usage, record.selector)]
    ]


def _matches(record: TLSA, certificate: bytes) -> bool:
    # RFC 6698 sections 2.1.2 and 2.1.3: selector 1 is DER SPKI, not
    # just the raw public-key bits or a PEM representation.
    selected = certificate
    if record.selector == 1:
        selected = (
            x509.load_der_x509_certificate(certificate)
            .public_key()
            .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        )
    if record.mtype == 1:
        selected = hashlib.sha256(selected).digest()
    elif record.mtype == 2:
        selected = hashlib.sha512(selected).digest()
    return selected == record.cert


def _starttls_certificates(
    hostname: str, context: ssl.SSLContext, timeout: float
) -> tuple[bytes, list[bytes] | None]:
    """Read certificates from port 25; send no mail or post-TLS commands."""
    server = smtplib.SMTP(hostname, port=25, timeout=timeout)
    try:
        server.ehlo_or_helo_if_needed()
        # SMTP.starttls checks the extension and sends the hostname as SNI
        # (RFC 7672 section 8.1). The TLSA port must match the TLS connection
        # (RFC 6698 section 4); never substitute an implicit TLS/465 probe.
        server.starttls(context=context)
        if server.sock is None:
            raise smtplib.SMTPServerDisconnected("No TLS socket after STARTTLS")
        socket = cast(ssl.SSLSocket, server.sock)
        leaf = socket.getpeercert(binary_form=True)
        if not leaf:
            raise ssl.SSLError("The SMTP server did not provide a certificate")
        # The public chain API was added in Python 3.13. Do not use private
        # _ssl internals on older supported Python versions.
        get_chain = getattr(socket, "get_unverified_chain", None)
        chain = cast(list[bytes], get_chain()) if callable(get_chain) else None
        return leaf, chain
    finally:
        server.close()


def _check_tlsa_certificate(
    hostname: str,
    authenticated_tlsa: list[str],
    *,
    timeout: float = DEFAULT_SMTP_TIMEOUT,
) -> TLSACertificateResult:
    """Check host certificates using TLSA data authenticated by dnssec.py.

    This private helper requires authenticated records for _25._tcp.hostname.
    A successful result describes the observed host only: the MX route that
    selected it has not been authenticated here. Nothing is cached. ``None``
    means no comparison could be completed, and ``reason`` explains why.
    """
    if not authenticated_tlsa:
        return {"matched": None, "reason": "No authenticated TLSA records available"}
    records = _usable_records(authenticated_tlsa)
    if not records:
        return {"matched": None, "reason": "No usable SMTP DANE TLSA records"}
    hostname = normalize_domain(hostname)
    # RFC 7672 section 3.1.1: DANE-EE(3) authenticates the leaf through
    # its TLSA binding, so ordinary certificate issuer/name/expiry checks
    # would wrongly reject valid self-signed or expired pinned certificates.
    # This connection is closed after reading certificates, without mail.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        leaf, chain = _starttls_certificates(hostname, context, timeout)
        for record in records:
            if record.usage == 3 and _matches(record, leaf):
                return {"matched": True, "reason": "Matched DANE-EE(3) TLSA record"}

        anchors: set[bytes] = set()
        unavailable_chain = False
        for record in records:
            if record.usage != 2:
                continue
            if record.selector == 0 and record.mtype == 0:
                # RFC 7671 section 5.2.2: a full TA certificate from DNS
                # must work even if the server omits it from its chain.
                anchors.add(record.cert)
            elif chain is None:
                unavailable_chain = True
            else:
                for certificate in chain:
                    if _matches(record, certificate):
                        anchors.add(certificate)
        if anchors:
            # RFC 7672 sections 3.1.2 and 3.2.2: DANE-TA(2) requires a
            # validated path to the specified TA and a matching host name.
            # Starting with an empty store prevents ordinary public CAs from
            # bypassing the TLSA association. PARTIAL_CHAIN allows a pinned
            # intermediate to be the trust anchor, without its root CA.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
            context.hostname_checks_common_name = True
            for anchor in anchors:
                context.load_verify_locations(cadata=anchor)
            try:
                _starttls_certificates(hostname, context, timeout)
            except ssl.SSLCertVerificationError as error:
                if unavailable_chain:
                    return {
                        "matched": None,
                        "reason": "A DANE-TA chain failed validation and other TA records "
                        "require Python 3.13 or newer to inspect the peer chain",
                    }
                return {
                    "matched": False,
                    "reason": f"DANE-TA(2) certificate validation failed: {error}",
                }
            return {"matched": True, "reason": "Validated DANE-TA(2) certificate chain"}
        if unavailable_chain:
            return {
                "matched": None,
                "reason": "DANE-TA(2) matching requires Python 3.13 or newer "
                "to inspect the peer certificate chain",
            }
        return {
            "matched": False,
            "reason": "The server certificate chain does not match a usable TLSA record",
        }
    except (OSError, smtplib.SMTPException, ValueError, UnsupportedAlgorithm) as error:
        return {
            "matched": None,
            "reason": f"SMTP certificate check unavailable: {error}",
        }
