# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import logging
from typing import Any, Dict

from lib.cuckoo.common.utils import convert_to_printable

try:
    from peepdf.JSAnalysis import analyseJS, isJavascript
    from peepdf.PDFCore import PDFParser

    HAVE_PEEPDF = True
except ImportError:
    HAVE_PEEPDF = False
    print("OPTIONAL! Missed dependency: poetry run pip install peepdf-3")

log = logging.getLogger(__name__)


def _get_obj_val(pdf, version: int, obj):
    with contextlib.suppress(Exception):
        if obj.type == "reference":
            return pdf.body[version].getObject(obj.id)
    return obj


def _clean_string(value: str) -> str:
    # handle BOM for typical english unicode while avoiding some
    # invalid BOM seen in malicious PDFs (like using the utf16le BOM
    # for an ascii string)
    if value.startswith("\xfe\xff"):
        if not any(ord(x) for x in value[2::2]):
            return value[3::2]
    elif value.startswith("\xff\xfe"):
        if not any(ord(x) for x in value[3::2]):
            return value[2::2]
    return value


def _set_base_uri(pdf):
    try:
        for version in range(pdf.updates + 1):
            trailer, _ = pdf.trailer[version]
            if trailer is not None:
                elem = trailer.dict.getElementByName("/Root")
                if elem:
                    elem = _get_obj_val(pdf, version, elem)
                if elem:
                    elem = elem.getElementByName("/URI")
                if elem:
                    elem = _get_obj_val(pdf, version, elem)
                if elem:
                    elem = elem.getElementByName("/Base")
                if elem:
                    elem = _get_obj_val(pdf, version, elem)
                if elem:
                    return elem.getValue()
    except Exception as e:
        log.error(e, exc_info=True)
        return ""


def peepdf_parse(filepath: str, pdfresult: Dict[str, Any]) -> Dict[str, Any]:
    """Extract JavaScript from PDF objects."""

    if not HAVE_PEEPDF:
        return pdfresult

    log.debug("About to parse with PDFParser")
    parser = PDFParser()
    try:
        _, pdf = parser.parse(filepath, forceMode=True, looseMode=True, manualAnalysis=False)
    except Exception as e:
        log.debug("Error parsing pdf: {}".format(e))
        return pdfresult
    urlset = set()
    annoturiset = set()
    objects = []
    retobjects = []
    metadata = {}

    base_uri = _set_base_uri(pdf)
    if not base_uri:
        base_uri = ""

    for i, body in enumerate(pdf.body):
        metatmp = pdf.getBasicMetadata(i)
        if metatmp:
            metadata = metatmp
        objects = body.objects
        for index in objects:
            oid = objects[index].id
            offset = objects[index].offset
            size = objects[index].size
            details = objects[index].object
            obj_data = {
                "Object ID": oid,
                "Offset": offset,
                "Size": size,
            }
            if details.type == "stream":
                decoded_stream = details.decodedStream
                if isJavascript(decoded_stream.strip()):
                    jsdata = None
                    try:
                        jslist, unescapedbytes, urlsfound, errors, ctxdummy = analyseJS(decoded_stream.strip())
                        jsdata = jslist[0]
                    except Exception as e:
                        log.error(e, exc_info=True)
                        continue
                    if errors or jsdata is None:
                        continue
                    for url in urlsfound:
                        urlset.add(url)
                    # The following loop is required to "JSONify" the strings returned from PyV8.
                    # As PyV8 returns byte strings, we must parse out bytecode and
                    # replace it with an escape '\'. We can't use encode("string_escape")
                    # as this would mess up the new line representation which is used for
                    # beautifying the javascript code for Django's web interface.
                    ret_data = ""
                    for char in jsdata:
                        if ord(char) > 127:
                            tmp = f"\\x{char.encode().hex()}"
                        else:
                            tmp = char
                        ret_data += tmp
                    obj_data["Data"] = ret_data
                    retobjects.append(obj_data)
            elif details.type == "dictionary" and details.containsJScode:
                js_elem = details.getElementByName("/JS")
                if js_elem:
                    jsdata = None
                    try:
                        jslist, unescapedbytes, urlsfound, errors, ctxdummy = analyseJS(js_elem.value)
                        jsdata = jslist[0]
                    except Exception as e:
                        log.error(e, exc_info=True)
                        continue
                    if errors or not jsdata:
                        continue

                    urlset.update(urlsfound)
                    # The following loop is required to "JSONify" the strings returned from PyV8.
                    # As PyV8 returns byte strings, we must parse out bytecode and
                    # replace it with an escape '\'. We can't use encode("string_escape")
                    # as this would mess up the new line representation which is used for
                    # beautifying the javascript code for Django's web interface.
                    ret_data = ""
                    for char in jsdata:
                        if ord(char) > 127:
                            tmp = f"\\x{char.encode().hex()}"
                        else:
                            tmp = char
                        ret_data += tmp
                    obj_data["Data"] = ret_data
                    retobjects.append(obj_data)
            elif details.type == "dictionary" and details.hasElement("/A"):
                # verify it to be a link type annotation
                subtype_elem = details.getElementByName("/Subtype")
                type_elem = details.getElementByName("/Type")
                if not subtype_elem or not type_elem:
                    continue
                subtype_elem = _get_obj_val(pdf, i, subtype_elem)
                type_elem = _get_obj_val(pdf, i, type_elem)
                if subtype_elem.getValue() != "/Link" or type_elem.getValue() != "/Annot":
                    continue
                a_elem = details.getElementByName("/A")
                a_elem = _get_obj_val(pdf, i, a_elem)
                if a_elem and a_elem.type == "dictionary" and a_elem.hasElement("/URI"):
                    uri_elem = a_elem.getElementByName("/URI")
                    if uri_elem:
                        uri_elem = _get_obj_val(pdf, i, uri_elem)
                        annoturiset.add(f"{base_uri}{uri_elem.getValue()}")
        pdfresult["JSStreams"] = retobjects
    if "creator" in metadata:
        pdfresult["Info"]["Creator"] = convert_to_printable(_clean_string(metadata["creator"]))
    if "producer" in metadata:
        pdfresult["Info"]["Producer"] = convert_to_printable(_clean_string(metadata["producer"]))
    if "author" in metadata:
        pdfresult["Info"]["Author"] = convert_to_printable(_clean_string(metadata["author"]))
    if len(urlset):
        pdfresult["JS_URLs"] = list(urlset)
    if len(annoturiset):
        pdfresult["Annot_URLs"] = list(annoturiset)

    return pdfresult
