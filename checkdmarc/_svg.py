"""Bounded SVG parsing and structural validation of the SVG Tiny PS profile.

This does not render images or verify their appearance, and is not a sanitizer.
The bundled schema leaves many paint and geometry values as unconstrained text.
"""

from __future__ import annotations

import hashlib
import math
import re
from importlib.resources import files
from threading import Lock
from typing import Any

import lxml.etree
import tinycss2
from tinycss2.ast import (
    CurlyBracketsBlock,
    FunctionBlock,
    ParenthesesBlock,
    ParseError,
    SquareBracketsBlock,
    StringToken,
    URLToken,
)

import checkdmarc.resources

MAX_SVG_BYTES = 1024 * 1024
_SVG_NAMESPACE = "http://www.w3.org/2000/svg"
_XML_WHITESPACE = " \t\r\n"
_NUMBER = r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?"
_SEPARATOR = r"(?:[ \t\r\n]+,?[ \t\r\n]*|,[ \t\r\n]*)"
_VIEWBOX = re.compile(_SEPARATOR.join([f"({_NUMBER})"] * 4))
_PIXEL_LENGTH = re.compile(f"({_NUMBER})(?:px)?")


def _xml_parser() -> lxml.etree.XMLParser:
    # These are separate controls: no_network alone does not prevent local
    # entity reads. Parse only supplied bytes and leave resource expansion off.
    return lxml.etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        decompress=False,
        huge_tree=False,
    )


# SVG Tiny PS draft 12 section 7 designates the BIMI Group schema as the
# authority. Load a reviewed, bundled copy rather than fetching it at runtime.
_SCHEMA = lxml.etree.RelaxNG(
    lxml.etree.fromstring(
        files(checkdmarc.resources).joinpath("SVG_PS.rng").read_bytes(),
        parser=_xml_parser(),
    )
)
# lxml's error log belongs to the validator and changes on each validation.
_SCHEMA_LOCK = Lock()


def _paint_reference_errors(value: str) -> list[str]:
    # SVG Tiny 1.2 sections 11.2/14.1.3 use FuncIRI for paint servers.
    # Tokenization handles quoted URLs, comments and escaped function names;
    # searching for the literal text "url(" would miss equivalent CSS forms.
    try:
        pending = tinycss2.parse_component_value_list(value, skip_comments=True)
    except ValueError:
        # Python limits conversion of very long integer tokens. This is an
        # input limit, not a reason to abort all checks of the customer domain.
        return ["The SVG paint value exceeds the parser's numeric limit"]
    errors: list[str] = []
    while pending:
        token = pending.pop()
        reference = None
        if isinstance(token, URLToken):
            reference = token.value
        elif isinstance(token, FunctionBlock):
            if token.lower_name == "url":
                arguments = [arg for arg in token.arguments if arg.type != "whitespace"]
                if len(arguments) == 1 and isinstance(arguments[0], StringToken):
                    reference = arguments[0].value
                else:
                    errors.append("The SVG paint URL is malformed")
            pending.extend(token.arguments)
        elif isinstance(
            token, (CurlyBracketsBlock, ParenthesesBlock, SquareBracketsBlock)
        ):
            pending.extend(token.content)
        elif isinstance(token, ParseError):
            errors.append("The SVG paint value contains invalid CSS syntax")
        if reference is not None and not reference.strip(_XML_WHITESPACE).startswith(
            "#"
        ):
            errors.append("External SVG paint references are not supported")
    return errors


def _reference_errors(svg: lxml.etree._Element) -> list[str]:
    # The profile aims for locally defined static graphics (PS draft 12
    # sections 2.3/3), but its schema leaves href/paint values as text. Apply
    # an explicit local processing policy: only same-document references.
    errors: list[str] = []
    if svg.getroottree().xpath("//processing-instruction('xml-stylesheet')"):
        errors.append("SVG stylesheet processing instructions are not supported")
    for element in svg.iter():
        if not isinstance(element.tag, str):
            continue
        # xml:base can make even a #fragment reference target another document.
        if element.get("{http://www.w3.org/XML/1998/namespace}base", "").strip():
            errors.append("Nonempty SVG xml:base values are not supported")
        for attribute, value in element.attrib.items():
            if lxml.etree.QName(attribute).localname == "href" and not value.strip(
                _XML_WHITESPACE
            ).startswith("#"):
                errors.append("External SVG href references are not supported")
            if attribute in ("fill", "stroke"):
                errors.extend(_paint_reference_errors(value))
    return errors


def _dimensions(
    svg: lxml.etree._Element, errors: list[str]
) -> tuple[float | None, float | None]:
    # SVG Tiny 1.2 section 7.8 permits four comma/whitespace-separated numbers,
    # "none", or no viewBox. Never invent dimensions for an unspecified viewport.
    view_box = svg.get("viewBox", "none").strip(_XML_WHITESPACE)
    view_dimensions: tuple[float | None, float | None] = (None, None)
    if view_box != "none":
        match = _VIEWBOX.fullmatch(view_box)
        if match is None:
            errors.append("The SVG viewBox must contain four numbers or none")
        else:
            numbers = tuple(float(value) for value in match.groups())
            if (
                not all(math.isfinite(value) for value in numbers)
                or min(numbers[2:]) < 0
            ):
                errors.append(
                    "The SVG viewBox dimensions must be finite and nonnegative"
                )
            else:
                view_dimensions = numbers[2], numbers[3]

    # Section 7.14 gives explicit absolute viewport dimensions precedence over
    # viewBox for aspect ratio. Physical units require a renderer's resolution;
    # expose only unitless/pixel dimensions, or the viewBox where appropriate.
    lengths = [svg.get(name, "").strip(_XML_WHITESPACE) for name in ("width", "height")]
    matches = [_PIXEL_LENGTH.fullmatch(value) for value in lengths]
    if all(match is not None for match in matches):
        dimensions = tuple(float(match[1]) for match in matches if match is not None)
        if all(math.isfinite(value) and value >= 0 for value in dimensions):
            return dimensions[0], dimensions[1]
    if any(not value or value.endswith("%") for value in lengths):
        return view_dimensions
    return None, None


def get_svg_metadata(raw_xml: str | bytes) -> dict[str, Any]:
    """Extract metadata and profile errors without loading referenced resources.

    The raw input is limited to 1 MiB. Width and height are null when intrinsic
    dimensions cannot be determined without rendering. The 32 KB profile size
    recommendation is reported as a warning, not a mandatory schema error.
    """
    raw_bytes = raw_xml if isinstance(raw_xml, bytes) else raw_xml.encode("utf-8")
    if len(raw_bytes) > MAX_SVG_BYTES:
        raise ValueError(
            f"SVG input exceeds the processing limit of {MAX_SVG_BYTES} bytes"
        )
    try:
        svg = lxml.etree.fromstring(raw_bytes, parser=_xml_parser())
    except lxml.etree.XMLSyntaxError as error:
        raise ValueError(f"Not an SVG file: {error}") from error
    if lxml.etree.QName(svg).localname != "svg":
        raise ValueError("Not an SVG file: the root element must be svg")
    if svg.getroottree().docinfo.doctype:
        raise ValueError("SVG document type declarations are not supported")

    errors = _reference_errors(svg)
    with _SCHEMA_LOCK:
        if not _SCHEMA.validate(svg):
            # The parser has its own bounded error log; keep the user-facing
            # result compact even when a document repeats a forbidden element.
            errors.extend(
                f"SVG Tiny PS schema: {error.message} (line {error.line})"
                for error in list(_SCHEMA.error_log)[:10]
            )
    warnings: list[str] = []
    # SVG Tiny PS draft 12 sections 2.1/2.4: title/desc must be nonempty;
    # the 64-character title and 32 KB file limits are recommendations.
    for element in svg.iter(f"{{{_SVG_NAMESPACE}}}desc", f"{{{_SVG_NAMESPACE}}}title"):
        if not "".join(element.itertext()).strip(_XML_WHITESPACE):
            errors.append(
                f"The SVG {lxml.etree.QName(element).localname} must not be empty"
            )
    title = svg.find(f"{{{_SVG_NAMESPACE}}}title")
    description = svg.find(f"{{{_SVG_NAMESPACE}}}desc")
    metadata: dict[str, Any] = {
        "svg_version": svg.get("version"),
        "filesize": f"{len(raw_bytes) / 1000} KB",
        # Hash exactly the bytes validated, including their original encoding.
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }
    for attribute, key in (
        ("baseProfile", "base_profile"),
        ("x", "x"),
        ("y", "y"),
        ("overflow", "overflow"),
    ):
        if attribute in svg.attrib:
            metadata[key] = svg.get(attribute)
    if title is not None:
        metadata["title"] = "".join(title.itertext())
        if len(metadata["title"]) > 64:
            warnings.append(
                "It is recommended that the SVG title contain no more than 64 characters"
            )
    if description is not None:
        metadata["description"] = "".join(description.itertext())
    if len(raw_bytes) > 32000:
        warnings.append("The SVG file exceeds the recommended size of 32 KB")
    metadata["width"], metadata["height"] = _dimensions(svg, errors)
    if errors:
        metadata["validation_errors"] = list(dict.fromkeys(errors))
    if warnings:
        metadata["warnings"] = warnings
    return metadata
