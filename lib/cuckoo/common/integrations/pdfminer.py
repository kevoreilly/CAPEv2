import logging
from typing import Any, Dict, Iterable, Set, Union

try:
    from pdfminer import pdfdocument, pdfparser, pdftypes

    HAVE_PDFMINER = True
except ImportError:
    HAVE_PDFMINER = False

log = logging.getLogger(__name__)


def _search_for_url(obj: Union[dict, list]) -> Iterable[str]:
    if obj is None:
        return

    if isinstance(obj, pdftypes.PDFStream):
        yield from _search_for_url(obj.attrs)
    elif isinstance(obj, list):
        for v in obj:
            yield from _search_for_url(v)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            if key == "URI":
                if isinstance(value, bytes):
                    yield value.decode()
                elif isinstance(value, str):
                    yield value
                continue

            yield from _search_for_url(value)


def _mine_for_urls(file_path: str) -> Set[str]:
    urls = set()
    try:
        with open(file_path, "rb") as f:
            parser = pdfparser.PDFParser(f)
            doc = pdfdocument.PDFDocument(parser)

            for xref in doc.xrefs:
                for object_id in xref.get_objids():
                    try:
                        obj = doc.getobj(object_id)
                        urls.update(_search_for_url(obj))
                    except Exception as ex:
                        log.error(ex, exc_info=True)
    except Exception as ex:
        log.error(ex, exc_info=True)

    return urls


def pdfminer_parse(filepath: str, pdfresult: Dict[str, Any]) -> Dict[str, Any]:
    if not HAVE_PDFMINER:
        return pdfresult

    urls = _mine_for_urls(filepath)
    pdfresult["All_URLs"] = list(urls)
    return pdfresult
