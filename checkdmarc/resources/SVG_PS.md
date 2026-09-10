# SVG Tiny PS schema

`SVG_PS.rng` is the XML Relax NG form of the BIMI Group's official
[SVG Tiny PS schema](https://bimigroup.org/resources/SVG_PS-latest.rnc.txt),
retrieved 2026-09-10. `SVG_PS.rnc` retains that source (with one attribution
comment added). The upstream source SHA-256 is `21aa62ccf4c718c34d816435afec4630981d47490d36b85b96a61529dff82932`.

The schema is a code component of [draft-svg-tiny-ps-abrotman-12,
section 7](https://datatracker.ietf.org/doc/html/draft-svg-tiny-ps-abrotman-12#section-7),
by Alex Brotman and Trent Adams. This is an Internet-Draft, not an RFC.
Section 7 identifies the BIMI Group copy as authoritative if the schemas
differ; the vendored file follows that copy without changing its rules.
The IETF Trust Revised BSD license is included in `SVG_PS.LICENSE` and in
the generated XML. See the [IETF Trust code component terms](https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/#:~:text=License%20to%20Code%20Components).

The conversion used `rnc2rng` 2.7.0 (a development tool, not a runtime
dependency): `rnc2rng.dumps(rnc2rng.loads(source_text))`. The license comment
was then added to the XML. Updating this resource requires reviewing the
upstream changes, regenerating the XML, and running the offline SVG tests.
No schema downloads or conversion occur while checking a domain.

The schema checks element/attribute structure and constrained values.
checkdmarc also checks nonempty title/description text, SVG viewBox syntax,
and rejects external references under its local processing policy.
It does not render images, verify the required two-color appearance, or
validate every path/paint/geometry string that this schema leaves as text.
A passing result is not an SVG sanitizer or authorization to inline an
untrusted SVG in a web page.
