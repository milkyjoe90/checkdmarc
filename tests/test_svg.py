"""Offline SVG profile tests using the bundled schema and real XML/CSS parsers."""

import html
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from checkdmarc._svg import MAX_SVG_BYTES
from checkdmarc.bimi import check_svg_requirements, get_svg_metadata, parse_bimi_record


def _svg(content="", attributes='viewBox="0 0 64 64"'):
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" '
        f'baseProfile="tiny-ps" {attributes}>'
        f"<title>Example Brand</title>{content}</svg>"
    )


class TestSVGProfile(unittest.TestCase):
    def testForbiddenElementsAndAttributesAreReported(self):
        for content, attributes in (
            ("<script>void 0;</script>", ""),
            ('<image href="https://example.test/image.png"/>', ""),
            ("<g><script>void 0;</script></g>", ""),
            ('<animate attributeName="x"/>', ""),
            ('<a href="#logo"><rect width="1" height="1"/></a>', ""),
            ("<foreignObject/>", ""),
            ("<style>rect {fill:red}</style>", ""),
            ("", 'onload="void 0;"'),
            ("", 'externalResourcesRequired="true"'),
        ):
            with self.subTest(content=content, attributes=attributes):
                errors = check_svg_requirements(
                    get_svg_metadata(_svg(content, attributes))
                )
                self.assertTrue(
                    any("SVG Tiny PS schema:" in error for error in errors), errors
                )

    def testNamespaceIsRequiredAndPrefixesWork(self):
        invalid = _svg().replace(
            'xmlns="http://www.w3.org/2000/svg"', 'xmlns="urn:other"'
        )
        self.assertTrue(check_svg_requirements(get_svg_metadata(invalid)))
        prefixed = (
            '<s:svg xmlns:s="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">'
            "<s:title>Brand</s:title></s:svg>"
        )
        self.assertEqual(check_svg_requirements(get_svg_metadata(prefixed)), [])

    def testTitlesAndDescriptionsFollowProfile(self):
        for invalid in (
            _svg().replace("Example Brand", ""),
            _svg().replace("Example Brand", " \t "),
            _svg("<title>Duplicate</title>"),
            _svg("<desc/>"),
            _svg("<desc> \n </desc>"),
        ):
            with self.subTest(svg=invalid):
                self.assertTrue(check_svg_requirements(get_svg_metadata(invalid)))
        metadata = get_svg_metadata(_svg("<desc>A useful description</desc>"))
        self.assertEqual(metadata["description"], "A useful description")
        self.assertEqual(check_svg_requirements(metadata), [])
        long_title = get_svg_metadata(_svg().replace("Example Brand", "B" * 65))
        self.assertEqual(check_svg_requirements(long_title), [])
        self.assertIn("64 characters", long_title["warnings"][0])

    def testOrdinaryShapesAndInternalPaintAndUseAreAccepted(self):
        shapes = (
            '<defs><linearGradient id="paint"><stop offset="0" stop-color="red"/>'
            '<stop offset="1" stop-color="blue"/></linearGradient></defs>'
            '<g><rect id="logo" width="64" height="64" fill="url(#paint)"/>'
            '<circle cx="32" cy="32" r="12" fill="white"/></g>'
            '<use href="#logo"/>'
        )
        self.assertEqual(check_svg_requirements(get_svg_metadata(_svg(shapes))), [])

    def testExternalReferencesAndBaseURIsAreRejected(self):
        for content, attributes in (
            ('<use href="https://example.test/other.svg#logo"/>', ""),
            ('<use href="other.svg#logo"/>', ""),
            ('<use href="//example.test/other.svg#logo"/>', ""),
            ('<use href="data:image/svg+xml,svg"/>', ""),
            ('<use href="#logo"/>', 'xml:base="https://example.test/other.svg"'),
            ('<g xml:base="../other.svg"><use href="#logo"/></g>', ""),
        ):
            with self.subTest(content=content, attributes=attributes):
                errors = check_svg_requirements(
                    get_svg_metadata(_svg(content, attributes))
                )
                self.assertTrue(
                    any("not supported" in error for error in errors), errors
                )

    def testEscapedAndQuotedExternalPaintURLsAreRejected(self):
        for value in (
            "url(https://example.test/paint.svg#color)",
            "URL('https://example.test/paint.svg#color')",
            r"u\72l(https://example.test/paint.svg#color)",
            r'url("\68 ttps://example.test/paint.svg#color")',
            'url("https://example.test/paint.svg#color" /*comment*/)',
            "url(../paint.svg#color)",
            "url(data:image/svg+xml,svg)",
            "[url(https://example.test/paint.svg)]",
        ):
            with self.subTest(value=value):
                content = f'<rect fill="{html.escape(value, quote=True)}"/>'
                errors = check_svg_requirements(get_svg_metadata(_svg(content)))
                self.assertIn("External SVG paint references are not supported", errors)

    def testEscapedAndQuotedInternalPaintURLsAreAccepted(self):
        for value in (
            "url(#paint)",
            "url('#paint')",
            r"u\72l(#paint)",
            r'url("\23paint")',
        ):
            with self.subTest(value=value):
                content = (
                    '<defs><solidColor id="paint" solid-color="red"/></defs>'
                    f'<rect fill="{html.escape(value, quote=True)}"/>'
                )
                self.assertEqual(
                    check_svg_requirements(get_svg_metadata(_svg(content))), []
                )

    def testMalformedPaintIsAValidationError(self):
        for value in ('url("#paint" invalid)', "url(bad url)", "9" * 5000):
            with self.subTest(value=value[:40]):
                content = f'<rect fill="{html.escape(value, quote=True)}"/>'
                self.assertTrue(check_svg_requirements(get_svg_metadata(_svg(content))))

    def testStylesheetInstructionOutsideRootIsRejected(self):
        instruction = (
            '<?xml-stylesheet href="https://example.test/style.css" type="text/css"?>'
        )
        for xml in (instruction + _svg(), _svg() + instruction, _svg(instruction)):
            with self.subTest(xml=xml):
                errors = check_svg_requirements(get_svg_metadata(xml))
                self.assertIn(
                    "SVG stylesheet processing instructions are not supported", errors
                )

    def testDocumentTypeAndEntityInputsAreRejected(self):
        for doctype in (
            '<!DOCTYPE svg SYSTEM "https://example.test/definition.dtd">',
            '<!DOCTYPE svg [<!ENTITY local SYSTEM "file:///no-such-audit-file">]>',
            '<!DOCTYPE svg [<!ENTITY local "expanded">]>',
        ):
            with (
                self.subTest(doctype=doctype),
                self.assertRaisesRegex(ValueError, "document type"),
            ):
                get_svg_metadata(doctype + _svg().replace("Example Brand", "&local;"))

    def testOversizedAndDeepInputsFailWithoutAbort(self):
        with self.assertRaisesRegex(ValueError, "processing limit"):
            get_svg_metadata(b"X" * (MAX_SVG_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "Not an SVG file"):
            get_svg_metadata(_svg("<g>" * 300 + "</g>" * 300))
        with self.assertRaisesRegex(ValueError, "root element"):
            get_svg_metadata("<other/>")

    def testViewBoxIsOptionalAndNoneIsValid(self):
        shapes = (
            '<rect width="400" height="400" fill="teal"/><circle r="125" fill="white"/>'
        )
        for attributes, expected in (
            ('width="400px" height="400px"', (400.0, 400.0)),
            ('viewBox="none" width="400" height="400"', (400.0, 400.0)),
            ("", (None, None)),
            ('width="50%" height="50%"', (None, None)),
            ('width="1cm" height="1cm"', (None, None)),
            ('viewBox="0, 0,64,64"', (64.0, 64.0)),
            ('viewBox="-1, +2,6.4e1,64."', (64.0, 64.0)),
            ('width="30" height="20" viewBox="0 0 64 64"', (30.0, 20.0)),
        ):
            with self.subTest(attributes=attributes):
                metadata = get_svg_metadata(_svg(shapes, attributes))
                self.assertEqual(check_svg_requirements(metadata), [])
                self.assertEqual((metadata["width"], metadata["height"]), expected)

    def testMalformedViewBoxHasStructuredErrors(self):
        for value in (
            "0 0 64",
            "0,,0,64,64",
            "0 0 nan 64",
            "0 0 -1 64",
            "0 0 1e999 64",
        ):
            with self.subTest(value=value):
                errors = check_svg_requirements(
                    get_svg_metadata(_svg(attributes=f'viewBox="{value}"'))
                )
                self.assertTrue(any("viewBox" in error for error in errors), errors)

    def testProfileErrorsRemainCorrectDuringConcurrentChecks(self):
        inputs = [_svg(), _svg("<script/>")] * 10
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(get_svg_metadata, inputs))
        for i, result in enumerate(results):
            self.assertEqual(bool(check_svg_requirements(result)), bool(i % 2))

    def testBIMISurfacesProfileErrorsAndRecommendations(self):
        with patch("requests.Session.get") as get:
            get.return_value.content = (_svg("<script/>") + " " * 32000).encode()
            result = parse_bimi_record("v=BIMI1; l=https://example.test/logo.svg")
        self.assertTrue(result["image"]["validation_errors"])
        self.assertTrue(
            any("recommended size of 32 KB" in w for w in result["warnings"])
        )
        with patch("requests.Session.get") as get:
            get.return_value.content = _svg(attributes="").encode()
            result = parse_bimi_record("v=BIMI1; l=https://example.test/logo.svg")
        self.assertIsNone(result["image"]["width"])
        self.assertFalse(any("square" in w for w in result["warnings"]))
