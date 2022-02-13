import logging

from lib.cuckoo.common.utils import convert_to_printable

try:
    import v8py

    HAVE_V8PY = True
except ImportError:
    HAVE_V8PY = False


try:
    from peepdf.JSAnalysis import analyseJS
    from peepdf.PDFCore import PDFParser

    HAVE_PEEPDF = True
except ImportError as e:
    HAVE_PEEPDF = False
    print(
        "Missed peepdf library: pip3 install https://github.com/CAPESandbox/peepdf/archive/20eda78d7d77fc5b3b652ffc2d8a5b0af796e3dd.zip#egg=peepdf==0.4.2"
    )

log = logging.getLogger(__name__)


def _get_obj_val(pdf, version, obj):
    try:
        if obj.type == "reference":
            return pdf.body[version].getObject(obj.id)
    except Exception:
        pass
    return obj


def _clean_string(value):
    # handle BOM for typical english unicode while avoiding some
    # invalid BOM seen in malicious PDFs (like using the utf16le BOM
    # for an ascii string)
    if value.startswith("\xfe\xff"):
        clean = True
        for x in value[2::2]:
            if ord(x):
                clean = False
                break
        if clean:
            return value[3::2]
    elif value.startswith("\xff\xfe"):
        clean = True
        for x in value[3::2]:
            if ord(x):
                clean = False
                break
        if clean:
            return value[2::2]
    return value


def _set_base_uri(pdf):
    try:
        for version in range(pdf.updates + 1):
            trailer, _ = pdf.trailer[version]
            if trailer is not None:
                elem = trailer.dict.getElementByName("/Root")
                if elem:
                    elem = _get_obj_val(version, elem)
                    if elem:
                        elem = elem.getElementByName("/URI")
                        if elem:
                            elem = _get_obj_val(version, elem)
                            if elem:
                                elem = elem.getElementByName("/Base")
                                if elem:
                                    elem = _get_obj_val(version, elem)
                                    if elem:
                                        return elem.getValue()
    except Exception as e:
        log.error(e, exc_info=True)
        pass


def peepdf_parse(filepath, pdfresult):
    """Uses V8Py from peepdf to extract JavaScript from PDF objects."""

    if not HAVE_PEEPDF:
        return pdfresult

    log.debug("About to parse with PDFParser")
    parser = PDFParser()
    _, pdf = parser.parse(filepath, forceMode=True, looseMode=True, manualAnalysis=False)
    urlset = set()
    annoturiset = set()
    objects = []
    retobjects = []
    metadata = {}

    base_uri = _set_base_uri()

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
            obj_data = {}
            obj_data["Object ID"] = oid
            obj_data["Offset"] = offset
            obj_data["Size"] = size
            if details.type == "stream":
                encoded_stream = details.encodedStream
                decoded_stream = details.decodedStream
                if HAVE_V8PY:
                    jsdata = None
                    try:
                        jslist, unescapedbytes, urlsfound, errors, ctxdummy = analyseJS(decoded_stream.strip())
                        jsdata = jslist[0]
                    except Exception as e:
                        log.error(e, exc_info=True)
                        continue
                    if len(errors):
                        continue
                    if jsdata is None:
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
                else:
                    continue
                obj_data["Data"] = ret_data
                retobjects.append(obj_data)
            elif details.type == "dictionary" and details.hasElement("/A"):
                # verify it to be a link type annotation
                subtype_elem = details.getElementByName("/Subtype")
                type_elem = details.getElementByName("/Type")
                if not subtype_elem or not type_elem:
                    continue
                subtype_elem = _get_obj_val(i, subtype_elem)
                type_elem = _get_obj_val(i, type_elem)
                if subtype_elem.getValue() != "/Link" or type_elem.getValue() != "/Annot":
                    continue
                a_elem = details.getElementByName("/A")
                a_elem = _get_obj_val(i, a_elem)
                if a_elem.type == "dictionary" and a_elem.hasElement("/URI"):
                    uri_elem = a_elem.getElementByName("/URI")
                    uri_elem = _get_obj_val(i, uri_elem)
                    annoturiset.add(base_uri + uri_elem.getValue())
            else:
                # can be dictionaries, arrays, etc, don't bother displaying them
                # all for now
                pass
                # obj_data["File Type"] = "Encoded"
                # obj_data["Data"] = "Encoded"
                # retobjects.append(obj_data)
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
