# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import hashlib
import io
import logging
import os
import xml.dom.minidom
import zipfile
from types import SimpleNamespace
from typing import Any, Dict, Optional

import lib.cuckoo.common.integrations.vbadeobf as vbadeobf
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists, path_mkdir, path_read_file, path_write_file
from lib.cuckoo.common.utils import convert_to_printable

try:
    import olefile

    HAVE_OLEFILE = True
except ImportError:
    HAVE_OLEFILE = False
    print("Missed olefile dependency: poetry run pip install olefile")

try:
    from csv import Error as csv_error

    import oletools.olevba
    from oletools import oleobj
    from oletools.msodde import process_file as extract_dde
    from oletools.oleid import OleID
    from oletools.olevba import UnexpectedDataError, VBA_Parser, detect_autoexec, detect_hex_strings, detect_suspicious, filter_vba
    from oletools.rtfobj import RtfObjParser, is_rtf

    # disable this noisy logging
    old_enable_logging = oletools.olevba.enable_logging

    def enable_logging():
        log = logging.getLogger(__name__)
        log.setLevel(logging.CRITICAL)

    oletools.olevba.enable_logging = enable_logging

    HAVE_OLETOOLS = True
except ImportError:
    print("Missed oletools dependency: poetry run pip install oletools")
    HAVE_OLETOOLS = False

try:
    from pcodedmp import pcodedmp as _pcodedmp

    HAVE_PCODEDMP = True
except ImportError:
    _pcodedmp = None
    HAVE_PCODEDMP = False

logging.getLogger("msodde").setLevel(logging.CRITICAL)
logging.getLogger("olevba").setLevel(logging.CRITICAL)
logging.getLogger("crypto").setLevel(logging.CRITICAL)

processing_conf = Config("processing")

HAVE_VBA2GRAPH = False
if not processing_conf.vba2graph.on_demand:
    from lib.cuckoo.common.integrations.vba2graph import HAVE_VBA2GRAPH, vba2graph_func

HAVE_XLM_DEOBF = False
if not processing_conf.xlsdeobf.on_demand:
    from lib.cuckoo.common.integrations.XLMMacroDeobfuscator import HAVE_XLM_DEOBF, xlmdeobfuscate


log = logging.getLogger(__name__)


class Office:
    """Office Document Static Analysis
    Supported formats:
    - Word 97-2003 (.doc, .dot), Word 2007+ (.docm, .dotm)
    - Excel 97-2003 (.xls), Excel 2007+ (.xlsm, .xlsb)
    - PowerPoint 97-2003 (.ppt), PowerPoint 2007+ (.pptm, .ppsm)
    - Word/PowerPoint 2007+ XML (aka Flat OPC)
    - Word 2003 XML (.xml)
    - Word/Excel Single File Web Page / MHTML (.mht)
    - Publisher (.pub)
    - Rich Text Format (.rtf)

    Office Document Static Analysis

    This class provides methods to perform static analysis on various Office document formats.
    Supported formats include:

    Attributes:
        file_path (str): Path to the file to be analyzed.
        options (Dict[str, str]): Analysis options.
        task_id (str): Task identifier.
        sha256 (str): SHA-256 hash of the file.

    Methods:
        _get_meta(meta) -> Dict[str, Dict[str, str]]:
            Extracts metadata from OLE files.

        _get_xml_meta(filepath) -> Dict[str, Dict[str, str]]:
            Extracts metadata from XML files within Office documents.

        _parse_rtf(data: bytes) -> Dict[str, list]:
            Parses RTF data and extracts embedded objects.

        _parse(filepath: str) -> Dict[str, Any]:
            Parses an Office document for static information.

        run() -> Dict[str, Any]:
            Runs the analysis and returns the results.

    """

    def __init__(self, file_path: str, task_id: str, sha256: str, options: Dict[str, str]):
        self.file_path = file_path
        self.options = options
        self.task_id = task_id
        self.sha256 = sha256
        self.extracted_files: list[tuple[str, bytes]] = []
        self._extracted_sha256s: set[str] = set()

    def _record_extracted_file(self, filename: str, payload: bytes, sha256: Optional[str] = None) -> None:
        if not payload:
            return
        digest = sha256 or hashlib.sha256(payload).hexdigest()
        if digest in self._extracted_sha256s:
            return
        self._extracted_sha256s.add(digest)
        self.extracted_files.append((filename or digest, payload))

    def _get_meta(self, meta) -> Dict[str, Dict[str, str]]:
        ret = {"SummaryInformation": {}}
        for prop in meta.SUMMARY_ATTRIBS:
            value = getattr(meta, prop)
            if not value:
                continue
            ret["SummaryInformation"][prop] = convert_to_printable(str(value))
        ret["DocumentSummaryInformation"] = {}
        for prop in meta.DOCSUM_ATTRIBS:
            value = getattr(meta, prop)
            if not value:
                continue
            ret["DocumentSummaryInformation"][prop] = convert_to_printable(str(value))
        return ret

    def _get_xml_meta(self, filepath) -> Dict[str, Dict[str, str]]:
        try:
            with zipfile.ZipFile(filepath) as zfile:
                core = xml.dom.minidom.parseString(zfile.read("docProps/core.xml"))
                app = xml.dom.minidom.parseString(zfile.read("docProps/app.xml"))
        except zipfile.BadZipFile:
            return {}

        metares = {"SummaryInformation": {}, "DocumentSummaryInformation": {}}

        for elem in core._get_documentElement().childNodes:
            try:
                if isinstance(elem, xml.dom.minidom.Text):
                    continue

                n = elem._get_tagName()
                data = core.getElementsByTagName(n)
                if not data:
                    continue

                data = data[0].childNodes
                if not data:
                    continue

                if not hasattr(data[0], "data"):
                    continue
                metares["SummaryInformation"][n.split(":")[1]] = convert_to_printable(data[0].data)
            except (IndexError, AttributeError) as e:
                log.exception(e)

        for elem in app._get_documentElement().childNodes:
            try:
                n = elem._get_tagName()
                data = app.getElementsByTagName(n)
                if not data:
                    continue

                data = data[0].childNodes
                if not data:
                    continue

                if not hasattr(data[0], "data"):
                    continue
                metares["DocumentSummaryInformation"][n] = convert_to_printable(data[0].data)
            except (IndexError, AttributeError) as e:
                log.exception(e)

        return metares

    def _parse_rtf(self, data: bytes) -> Dict[str, list]:
        results = {}
        rtfp = RtfObjParser(data)
        rtfp.parse()
        save_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", self.task_id, "rtf_objects")
        if rtfp.objects and not path_exists(save_dir):
            path_mkdir(save_dir, exist_ok=True)
        for rtfobj in rtfp.objects:
            results.setdefault(str(rtfobj.format_id), [])
            temp_dict = {"class_name": "", "size": "", "filename": "", "type_embed": "", "CVE": "", "sha256": "", "index": ""}

            if rtfobj.is_package:
                log.debug("Saving file from OLE Package in object #%d:", rtfobj.format_id)
                log.debug("  Filename = %s", rtfobj.filename)
                log.debug("  Source path = %s", rtfobj.src_path)
                log.debug("  Temp path = %s", rtfobj.temp_path)
                sha256 = hashlib.sha256(rtfobj.olepkgdata).hexdigest()
                fname = convert_to_printable(rtfobj.filename) if rtfobj.filename else sha256
                log.debug("  Saving to file %s", sha256)
                temp_dict["filename"] = fname
                _ = path_write_file(os.path.join(save_dir, sha256), rtfobj.olepkgdata)
                temp_dict["sha256"] = sha256
                temp_dict["size"] = len(rtfobj.olepkgdata)
                self._record_extracted_file(fname, rtfobj.olepkgdata, sha256=sha256)
                # temp_dict["source_path"] = convert_to_printable(rtfobj.src_path))
            elif rtfobj.is_ole and rtfobj.oledata_size is not None:
                ole_object_mapping = {oleobj.OleObject.TYPE_EMBEDDED: "Embedded", oleobj.OleObject.TYPE_LINKED: "Linked"}
                temp_dict["type_embed"] = ole_object_mapping.get(rtfobj.format_id, "Unknown")
                if getattr(rtfobj, "clsid", None) is not None and "CVE" in rtfobj.clsid_desc:
                    temp_dict["CVE"] = rtfobj.clsid_desc
                # Detect OLE2Link exploit
                # http://www.kb.cert.org/vuls/id/921560
                if rtfobj.class_name == b"OLE2Link":
                    temp_dict["CVE"] = "Possibly an exploit for the OLE2Link vulnerability (VU#921560, CVE-2017-0199)"
                log.debug("Saving file embedded in OLE object #%d:", rtfobj.format_id)
                log.debug("  format_id  = %d", rtfobj.format_id)
                log.debug("  class name = %s", rtfobj.class_name)
                log.debug("  data size  = %d", rtfobj.oledata_size)
                class_name = rtfobj.class_name.decode("ascii", "ignore").encode("ascii")
                temp_dict["class_name"] = convert_to_printable(class_name)
                temp_dict["size"] = rtfobj.oledata_size
                # set a file extension according to the class name:
                class_name = rtfobj.class_name.lower()
                if class_name.startswith(b"word"):
                    ext = "doc"
                elif class_name.startswith(b"package"):
                    ext = "package"
                else:
                    ext = "bin"
                sha256 = hashlib.sha256(rtfobj.oledata).hexdigest()
                temp_dict["filename"] = f"object_{rtfobj.start:08X}.{ext}"
                save_path = os.path.join(save_dir, sha256)
                log.debug("  Saving to file %s", sha256)
                _ = path_write_file(save_path, rtfobj.oledata)
                temp_dict["sha256"] = sha256
                self._record_extracted_file(temp_dict["filename"], rtfobj.oledata, sha256=sha256)
            else:
                log.debug("Saving raw data in object #%d:", rtfobj.format_id)
                temp_dict["filename"] = f"object_{rtfobj.start:08X}.raw"
                sha256 = hashlib.sha256(rtfobj.rawdata).hexdigest()
                save_path = os.path.join(save_dir, sha256)
                log.debug("  Saving object to file %s", sha256)
                _ = path_write_file(save_path, rtfobj.rawdata)
                temp_dict["sha256"] = sha256
                temp_dict["size"] = len(rtfobj.rawdata)
                self._record_extracted_file(temp_dict["filename"], rtfobj.rawdata, sha256=sha256)
            temp_dict["index"] = f"{rtfobj.start:08X}h"
            results[str(rtfobj.format_id)].append(temp_dict)

        return results

    def _parse_ole_and_ooxml_objects(self, filepath: str) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
        external_relationships: list[dict[str, str]] = []
        embedded_objects: list[dict[str, Any]] = []
        xml_parser = None
        if oleobj.is_zipfile(filepath):
            try:
                xml_parser = oleobj.XmlParser(filepath)
                for rel_type, target in oleobj.find_external_relationships(xml_parser):
                    rel_str = rel_type.decode("utf-8", errors="replace") if isinstance(rel_type, bytes) else str(rel_type)
                    target_str = target.decode("utf-8", errors="replace") if isinstance(target, bytes) else str(target)
                    cve = ""
                    if target_str.lower().startswith("mhtml:"):
                        cve = "CVE-2021-40444"
                    elif rel_str == "attachedTemplate":
                        cve = "CVE-2017-0199"
                    external_relationships.append(
                        {
                            "relationship": convert_to_printable(rel_str),
                            "target": convert_to_printable(target_str),
                            "CVE": cve,
                        }
                    )
                for custom_item in oleobj.find_customUI(xml_parser):
                    target = (
                        custom_item[1]
                        if isinstance(custom_item, tuple) and len(custom_item) > 1
                        else custom_item[0]
                        if isinstance(custom_item, tuple)
                        else custom_item
                    )
                    if not target:
                        continue
                    target_str = target.decode("utf-8", errors="replace") if isinstance(target, bytes) else str(target)
                    external_relationships.append(
                        {
                            "relationship": "customUI",
                            "target": convert_to_printable(target_str),
                            "CVE": "CVE-2021-42292",
                        }
                    )
            except Exception as e:
                log.debug("Error parsing OOXML external relationships for %s: %s", filepath, e)

        save_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", self.task_id, "rtf_objects")
        try:
            for ole in oleobj.find_ole(filepath, None, xml_parser):
                if ole is None:
                    continue
                try:
                    for path_parts in ole.listdir():
                        if not path_parts or path_parts[-1].lower() != "\x01ole10native":
                            continue
                        stream = ole.openstream(path_parts)
                        try:
                            opkg = oleobj.OleNativeStream(stream)
                        finally:
                            stream.close()
                        if getattr(opkg, "is_link", False) or not getattr(opkg, "data", None):
                            continue
                        if not path_exists(save_dir):
                            path_mkdir(save_dir, exist_ok=True)
                        sha256 = hashlib.sha256(opkg.data).hexdigest()
                        raw_fname = getattr(opkg, "filename", None)
                        fname = convert_to_printable(raw_fname) if raw_fname else sha256
                        _ = path_write_file(os.path.join(save_dir, sha256), opkg.data)
                        self._record_extracted_file(fname, opkg.data, sha256=sha256)
                        embedded_objects.append(
                            {
                                "filename": fname,
                                "sha256": sha256,
                                "size": len(opkg.data),
                                "stream": convert_to_printable("/".join(path_parts)),
                            }
                        )
                finally:
                    with contextlib.suppress(Exception):
                        ole.close()
        except Exception as e:
            log.debug("Error extracting OLE objects from %s: %s", filepath, e)

        return external_relationships, embedded_objects

    def _parse(self, filepath: str) -> Dict[str, Any]:
        """Parses an office document for static information.
        @param filepath: Path to the file to be analyzed.
        @return: results dict or None
        """

        officeresults = {}
        self.extracted_files = []
        self._extracted_sha256s = set()
        if not HAVE_OLETOOLS:
            return officeresults

        vba = None
        rtf_file = is_rtf(filepath)
        if rtf_file:
            try:
                contents = path_read_file(filepath)
                temp_results = self._parse_rtf(contents)
                if temp_results:
                    officeresults["rtf"] = temp_results
            except Exception as e:
                log.exception(e)
        else:
            try:
                vba = VBA_Parser(filepath)
            except Exception as e:
                log.warning("Error initializing VBA_Parser for %s: %s", filepath, e)
                vba = None

        try:
            try:
                # extract DDE
                dde = extract_dde(filepath)
                if dde:
                    officeresults["dde"] = convert_to_printable(dde)
            except (csv_error, UnicodeDecodeError):
                pass
            except AttributeError:
                log.warning("OleFile library bug: AttributeError! fix: poetry run pip install olefile")
            except Exception as e:
                log.exception(e)

            officeresults["Metadata"] = {}
            macro_folder = os.path.join(CUCKOO_ROOT, "storage", "analyses", self.task_id, "macros")
            if olefile.isOleFile(filepath):
                try:
                    with olefile.OleFileIO(filepath) as ole:
                        meta = ole.get_metadata()
                        # must be left this way or we won't see the results
                        officeresults["Metadata"] = self._get_meta(meta)
                except AttributeError as e:
                    log.error("Problems with olefile library: %s", e)
            else:
                with contextlib.suppress(KeyError):
                    officeresults["Metadata"] = self._get_xml_meta(filepath)

            is_stomped = False
            with contextlib.suppress(Exception):
                is_stomped = bool(vba and vba.detect_vba_stomping())

            if vba and (vba.detect_vba_macros() or is_stomped):
                officeresults["Metadata"]["HasMacros"] = "Yes"
                # Create IOC and category vars. We do this before processing the
                # macro(s) to avoid overwriting data when there are multiple
                # macros in a single file.
                officeresults["Macro"] = {"Code": {}, "info": {}, "Analysis": {}}
                ctr = 0

                try:
                    for _, _, vba_filename, vba_code in vba.extract_macros():
                        vba_code = filter_vba(vba_code)
                        if vba_code.strip() != "":
                            # Handle all macros
                            ctr += 1
                            outputname = f"Macro{ctr}"
                            officeresults["Macro"]["Code"][outputname] = [
                                (convert_to_printable(vba_filename), convert_to_printable(vba_code))
                            ]
                            if not path_exists(macro_folder):
                                path_mkdir(macro_folder, exist_ok=True)
                            macro_file = os.path.join(macro_folder, outputname)
                            _ = path_write_file(macro_file, convert_to_printable(vba_code), mode="text")
                            officeresults["Macro"]["info"][outputname] = {"yara_macro": File(macro_file).get_yara(category="macro")}
                            officeresults["Macro"]["info"][outputname]["yara_macro"].extend(File(macro_file).get_yara(category="CAPE"))

                            try:
                                iocs = vbadeobf.parse_macro(vba_code)
                                for pattern, match in iocs:
                                    officeresults["Macro"]["Analysis"].setdefault("IOCs", []).append((pattern, match))
                            except ValueError as e:
                                log.error("Can't parse macros for %s - %s ", filepath, str(e))
                            except Exception as e:
                                log.exception(e)
                            for keyword, description in detect_autoexec(vba_code):
                                officeresults["Macro"]["Analysis"].setdefault("AutoExec", []).append(
                                    (keyword.replace(".", "_"), description)
                                )
                            for keyword, description in detect_suspicious(vba_code):
                                officeresults["Macro"]["Analysis"].setdefault("Suspicious", []).append(
                                    (keyword.replace(".", "_"), description)
                                )
                            for encoded, decoded in detect_hex_strings(vba_code):
                                officeresults["Macro"]["Analysis"].setdefault("HexStrings", []).append(
                                    (encoded, convert_to_printable(decoded))
                                )
                except (AssertionError, UnexpectedDataError, ValueError, AttributeError) as e:
                    log.warning("Macros in parse_office.py: %s", e)

                if is_stomped:
                    officeresults["Macro"]["Analysis"].setdefault("Suspicious", []).append(
                        ("VBA_Stomping", "VBA source code and P-code differ (possible VBA stomping)")
                    )
                    if HAVE_PCODEDMP:
                        try:
                            pcode_buf = io.StringIO()
                            _pcodedmp.processProject(
                                vba,
                                SimpleNamespace(disasmOnly=True, verbose=False),
                                output_file=pcode_buf,
                            )
                            pcode_text = pcode_buf.getvalue()
                            if pcode_text.strip():
                                if not path_exists(macro_folder):
                                    path_mkdir(macro_folder)
                                pcode_file = os.path.join(macro_folder, "pcode_dump")
                                _ = path_write_file(pcode_file, convert_to_printable(pcode_text), mode="text")
                                pcode_yara = File(pcode_file).get_yara(category="macro")
                                pcode_yara.extend(File(pcode_file).get_yara(category="CAPE"))
                                officeresults["Macro"]["info"]["PCode"] = {"yara_macro": pcode_yara}
                                try:
                                    for pattern, match in vbadeobf.parse_macro(pcode_text):
                                        officeresults["Macro"]["Analysis"].setdefault("IOCs", []).append((pattern, match))
                                except Exception as e:
                                    log.exception(e)
                                for keyword, description in detect_suspicious(pcode_text):
                                    officeresults["Macro"]["Analysis"].setdefault("Suspicious", []).append(
                                        (keyword.replace(".", "_"), description)
                                    )
                                officeresults["Macro"]["Code"]["PCode"] = [
                                    ("VBA P-Code", convert_to_printable(pcode_text))
                                ]
                        except Exception as e:
                            log.warning("Error extracting VBA P-Code for %s: %s", filepath, e)

                if HAVE_VBA2GRAPH:
                    vba2graph_func(filepath, self.task_id, self.sha256)

            else:
                officeresults["Metadata"]["HasMacros"] = "No"
        finally:
            if vba is not None:
                with contextlib.suppress(Exception):
                    vba.close()

        if not rtf_file:
            ext_rels, embedded_objs = self._parse_ole_and_ooxml_objects(filepath)
            if ext_rels:
                officeresults["external_relationships"] = ext_rels
            if embedded_objs:
                officeresults["embedded_objects"] = embedded_objs

        try:
            for indicator in OleID(filepath).check():
                if indicator.value and indicator.name in {"Word Document", "Excel Workbook", "PowerPoint Presentation"}:
                    officeresults["Metadata"]["DocumentType"] = indicator.name
        except Exception as e:
            log.exception(e)

        if HAVE_XLM_DEOBF:
            tmp_xlmmacro = xlmdeobfuscate(filepath, self.task_id, self.options.get("password", ""))
            if tmp_xlmmacro:
                officeresults["XLMMacroDeobfuscator"] = tmp_xlmmacro

        return officeresults

    def run(self) -> Dict[str, Any]:
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not path_exists(self.file_path):
            log.error("parse_office File not found: %s", self.file_path)
            return {}
        return self._parse(self.file_path)
