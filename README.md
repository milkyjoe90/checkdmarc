# checkdmarc

[![CI](https://github.com/domainaware/checkdmarc/actions/workflows/ci.yml/badge.svg)](https://github.com/domainaware/checkdmarc/actions/workflows/ci.yml)
[![Code Coverage](https://codecov.io/gh/domainaware/checkdmarc/branch/main/graph/badge.svg)](https://codecov.io/gh/domainaware/checkdmarc)
[![PyPI](https://img.shields.io/pypi/v/checkdmarc)](https://pypi.org/project/checkdmarc/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/checkdmarc?color=blue)](https://pypistats.org/packages/checkdmarc)

A Python module, command line utility, and [web application](https://github.com/domainaware/checkdmarc-web-frontend) for validating SPF and DMARC DNS records.

## Sponsors

This project is maintained by one developer.
Please consider [sponsoring my work](https://github.com/sponsors/seanthegeek) if you or your organization benefit from it.

## Features

- API, CLI, and web interfaces
- Can test multiple domains at once
- CLI output in JSON or CSV format
- DNSSEC signatures authenticated through parent zones to bundled IANA root keys
- SPF
  - Record validation
  - Counting of DNS lookups and void lookups
  - Counting of lookups per mechanism
- DMARC
  - Validation and parsing of DMARC records
  - Shows warnings when the DMARC record is made ineffective by `sp` values, or by use of the `pct`/`rf`/`ri` tags that were removed in RFC 9989
  - Checks for authorization records on reporting email addresses
- BIMI
  - Validation of the mark format and certificate against the [Minimum Security Requirements for Issuance of Mark Certificates](https://bimigroup.org/resources/VMC_Requirements_latest.pdf)
  - Parsing of the mark certificate
- MX records
  - Preference
  - IPv4 and IPv6 addresses
  - Optional STARTTLS and TLS testing (pass `--check-mx-tls`)
  - Optional host certificate matching against authenticated TLSA records (DANE-EE and DANE-TA)
- MTA-STS
- SMTP TLS reporting
  - Record and policy parsing and validation
- SOA record parsing
- Nameserver listing

## BIMI images

SVG checks use a bundled copy of the BIMI Group's SVG Tiny PS schema. Parsing
and downloads are limited to 1 MiB, and external image references are rejected.
The profile's recommended 32 KB size is a warning. Width and height can be
`null` when they cannot be determined without rendering.

These checks validate structure and selected profile rules; they do not render
the logo or validate every geometry value. A passing result does not make an
untrusted SVG safe to inline in a web page. See the bundled
[schema provenance and limitations](https://github.com/domainaware/checkdmarc/blob/main/checkdmarc/resources/SVG_PS.md).

## DNSSEC results

`dnssec: true` means at least one checked record set was authenticated through
its parent zones to a bundled IANA root trust anchor. Keep the package current
for root key rollovers. Cached answers expire at the earliest DNS TTL or
signature expiration in that chain and are isolated by nameserver configuration.

`false` does not distinguish unsigned DNS, invalid signatures, and failed
lookups. The check does not authenticate denial of existence or wildcard
expansion. `tlsa` contains only authenticated records at the exact queried name;
CNAME/DNAME aliases and wildcard answers are not followed by this lookup.
The raw `get_dnskey()` library helper returns keys without authenticating them.

## TLSA certificate checks

With `--check-mx-tls`, each MX host's `tlsa_certificate.matched` is `true` when
its port 25 STARTTLS certificate matches authenticated TLSA data, `false` when
usable associations fail to match or DANE-TA certificate validation fails, and
`null` when unassessed or unavailable. `reason` explains the result. Without the
flag, certificate matching is unassessed. Ordinary `tls` and `starttls` results
continue to use normal public CA verification and can differ from TLSA matching.

DANE-EE usage 3 supports certificate and public key selectors with full,
SHA-256, or SHA-512 matching. It permits expired, self-signed, and differently
named certificates as required by RFC 7672. DANE-TA usage 2 validates the host
name and certificate chain using only the TLSA trust anchors. Full `2 0 0`
certificates work on all supported Python versions; other usage 2 forms require
Python 3.13 or newer's public peer certificate chain API. The strongest usable
digest is selected per usage and selector, while full matches remain eligible.
Checks may open two additional SMTP connections per host and are not cached.

This is a host certificate check, not a claim that the domain's complete DANE
mail delivery route is secure: the MX lookup that selects the host is not
DNSSEC-authenticated by this check, and TLSA aliases and wildcard proofs are
not supported. No mail is sent.

## Docker support

1. Build the image using `docker build . -t checkdmarc`
2. Use the image with a command like `docker run --rm checkdmarc google.nl`
