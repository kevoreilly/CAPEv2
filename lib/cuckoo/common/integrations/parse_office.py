# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import hashlib
import logging
import os
import xml.dom.minidom
import zipfile
from typing import Any, Dict

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
    print("Missed olefile dependency: pip3 install olefile")

try:
    from csv import Error as csv_error

    from oletools import oleobj
    from oletools.msodde import process_file as extract_dde
    from oletools.oleid import OleID
    from oletools.olevba import UnexpectedDataError, VBA_Parser, detect_autoexec, detect_hex_strings, detect_suspicious, filter_vba
    from oletools.rtfobj import RtfObjParser, is_rtf

    HAVE_OLETOOLS = True
except ImportError:
    print("Missed oletools dependency: pip3 install oletools")
    HAVE_OLETOOLS = False

logging.getLogger("msodde").setLevel(logging.CRITICAL)
logging.getLogger("olevba").setLevel(logging.CRITICAL)

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
    """

    def __init__(self, file_path: str, task_id: str, sha256: str, options: Dict[str, str]):
        self.file_path = file_path
        self.options = options
        self.task_id = task_id
        self.sha256 = sha256

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
            n = elem._get_tagName()
            try:
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
                log.error(e, exc_info=True)

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
                log.error(e, exc_info=True)

        return metares

    def _parse_rtf(self, data: bytes) -> Dict[str, list]:
        results = {}
        rtfp = RtfObjParser(data)
        rtfp.parse()
        save_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", self.task_id, "rtf_objects")
        if rtfp.objects and not path_exists(save_dir):
            path_mkdir(save_dir)
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
            else:
                log.debug("Saving raw data in object #%d:", rtfobj.format_id)
                temp_dict["filename"] = f"object_{rtfobj.start:08X}.raw"
                sha256 = hashlib.sha256(rtfobj.rawdata).hexdigest()
                save_path = os.path.join(save_dir, sha256)
                log.debug("  Saving object to file %s", sha256)
                _ = path_write_file(save_path, rtfobj.rawdata)
                temp_dict["sha256"] = sha256
                temp_dict["size"] = len(rtfobj.rawdata)
            temp_dict["index"] = f"{rtfobj.start:08X}h"
            results[str(rtfobj.format_id)].append(temp_dict)

        return results

    def _parse(self, filepath: str) -> Dict[str, Any]:
        """Parses an office document for static information.
        @param filepath: Path to the file to be analyzed.
        @return: results dict or None
        """

        results = {}
        if not HAVE_OLETOOLS:
            return results

        vba = False
        if is_rtf(filepath):
            try:

                contents = path_read_file(filepath)
                temp_results = self._parse_rtf(contents)
                if temp_results:
                    results["office_rtf"] = temp_results
            except Exception as e:
                log.error(e, exc_info=True)
        else:
            try:
                vba = VBA_Parser(filepath)
            except ValueError as e:
                log.error("Error VBA_Parser: %s", str(e))
            except Exception:
                return results
        try:
            # extract DDE
            dde = extract_dde(filepath)
            if dde:
                results["office_dde"] = convert_to_printable(dde)
        except (csv_error, UnicodeDecodeError):
            pass
        except AttributeError:
            log.warning("OleFile library bug: AttributeError! fix: pip3 install -U olefile")
        except Exception as e:
            log.error(e, exc_info=True)

        officeresults = {"Metadata": {}}
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
        if vba and vba.detect_vba_macros():
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
                            path_mkdir(macro_folder)
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
                            log.error(e, exc_info=True)
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
            except (AssertionError, UnexpectedDataError) as e:
                log.warning("Macros in static.py", e)

            if HAVE_VBA2GRAPH:
                vba2graph_func(filepath, self.task_id, self.sha256)

        else:
            officeresults["Metadata"]["HasMacros"] = "No"

        try:
            for indicator in OleID(filepath).check():
                if indicator.value and indicator.name in {"Word Document", "Excel Workbook", "PowerPoint Presentation"}:
                    officeresults["Metadata"]["DocumentType"] = indicator.name
        except Exception as e:
            log.error(e, exc_info=True)

        if HAVE_XLM_DEOBF:
            tmp_xlmmacro = xlmdeobfuscate(filepath, self.task_id, self.options.get("password", ""))
            if tmp_xlmmacro:
                officeresults["XLMMacroDeobfuscator"] = tmp_xlmmacro

        return officeresults

    def run(self) -> Dict[str, Any]:
        """Run analysis.
        @return: analysis results dict or None.
        """
        return self._parse(self.file_path) if path_exists(self.file_path) else None
