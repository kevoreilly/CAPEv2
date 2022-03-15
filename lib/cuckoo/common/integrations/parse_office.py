# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import logging
import os
import xml.dom.minidom
import zipfile

import lib.cuckoo.common.integrations.vbadeobf as vbadeobf
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
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

processing_conf = Config("processing")

HAVE_VBA2GRAPH = False
if not processing_conf.vba2graph.on_demand:
    from lib.cuckoo.common.integrations.vba2graph import HAVE_VBA2GRAPH, vba2graph_func

HAVE_XLM_DEOBF = False
if not processing_conf.xlsdeobf.on_demand:
    from lib.cuckoo.common.integrations.XLMMacroDeobfuscator import HAVE_XLM_DEOBF, xlmdeobfuscate


log = logging.getLogger(__name__)


class Office(object):
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

    def __init__(self, file_path, task_id, sha256, options):
        self.file_path = file_path
        self.options = options
        self.task_id = str(task_id)
        self.sha256 = sha256

    def _get_meta(self, meta):
        ret = {}
        ret["SummaryInformation"] = {}
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

    def _get_xml_meta(self, filepath):
        zfile = zipfile.ZipFile(filepath)
        core = xml.dom.minidom.parseString(zfile.read("docProps/core.xml"))
        app = xml.dom.minidom.parseString(zfile.read("docProps/app.xml"))

        metares = dict()
        metares["SummaryInformation"] = {}
        coretags = metares["SummaryInformation"]

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
                coretags[n.split(":")[1]] = convert_to_printable(data[0].data)
            except (IndexError, AttributeError) as e:
                log.error(e, exc_info=True)

        metares["DocumentSummaryInformation"] = {}
        apptags = metares["DocumentSummaryInformation"]

        for elem in app._get_documentElement().childNodes:
            n = elem._get_tagName()
            try:
                data = app.getElementsByTagName(n)
                if not data:
                    continue

                data = data[0].childNodes
                if not data:
                    continue

                if not hasattr(data[0], "data"):
                    continue

                apptags[n] = convert_to_printable(data[0].data)
            except (IndexError, AttributeError) as e:
                log.error(e, exc_info=True)

        return metares

    def _parse_rtf(self, data):
        results = {}
        rtfp = RtfObjParser(data)
        rtfp.parse()
        save_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", self.task_id, "rtf_objects")
        if rtfp.objects and not os.path.exists(save_dir):
            os.makedirs(save_dir)
        for rtfobj in rtfp.objects:
            results.setdefault(str(rtfobj.format_id), [])
            temp_dict = {}
            temp_dict["class_name"] = ""
            temp_dict["size"] = ""
            temp_dict["filename"] = ""
            temp_dict["type_embed"] = ""
            temp_dict["CVE"] = ""
            temp_dict["sha256"] = ""
            temp_dict["index"] = ""

            if rtfobj.is_package:
                log.debug("Saving file from OLE Package in object #%d:", rtfobj.format_id)
                log.debug("  Filename = %s", rtfobj.filename)
                log.debug("  Source path = %s", rtfobj.src_path)
                log.debug("  Temp path = %s", rtfobj.temp_path)
                sha256 = hashlib.sha256(rtfobj.olepkgdata).hexdigest()
                if rtfobj.filename:
                    fname = convert_to_printable(rtfobj.filename)
                else:
                    fname = sha256
                log.debug("  Saving to file %s", sha256)
                temp_dict["filename"] = fname
                open(os.path.join(save_dir, sha256), "wb").write(rtfobj.olepkgdata)
                temp_dict["sha256"] = sha256
                temp_dict["size"] = len(rtfobj.olepkgdata)
                # temp_dict["source_path"] = convert_to_printable(rtfobj.src_path))
            # When format_id=TYPE_LINKED, oledata_size=None
            elif rtfobj.is_ole and rtfobj.oledata_size is not None:
                # ole_column = f"format_id: {rtfobj.format_id} "
                if rtfobj.format_id == oleobj.OleObject.TYPE_EMBEDDED:
                    temp_dict["type_embed"] = "Embedded"
                elif rtfobj.format_id == oleobj.OleObject.TYPE_LINKED:
                    temp_dict["type_embed"] = "Linked"
                else:
                    temp_dict["type_embed"] = "Unknown"
                if hasattr(rtfobj, "clsid") and rtfobj.clsid is not None:
                    # ole_column += f"\nCLSID: {rtfobj.clsid}"
                    # ole_column += f"\n{rtfobj.clsid_desc}"
                    if "CVE" in rtfobj.clsid_desc:
                        temp_dict["CVE"] = rtfobj.clsid_desc
                # Detect OLE2Link exploit
                # http://www.kb.cert.org/vuls/id/921560
                if rtfobj.class_name == b"OLE2Link":
                    # ole_column += '\nPossibly an exploit for the OLE2Link vulnerability (VU#921560, CVE-2017-0199)'
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
                open(save_path, "wb").write(rtfobj.oledata)
                temp_dict["sha256"] = sha256
            else:
                log.debug("Saving raw data in object #%d:", rtfobj.format_id)
                temp_dict["filename"] = f"object_{rtfobj.start:08X}.raw"
                sha256 = hashlib.sha256(rtfobj.rawdata).hexdigest()
                save_path = os.path.join(save_dir, sha256)
                log.debug("  Saving object to file %s", sha256)
                open(save_path, "wb").write(rtfobj.rawdata)
                temp_dict["sha256"] = sha256
                temp_dict["size"] = len(rtfobj.rawdata)
            temp_dict["index"] = f"{rtfobj.start:08X}h"
            if temp_dict:
                results[str(rtfobj.format_id)].append(temp_dict)

        return results

    def _parse(self, filepath):
        """Parses an office document for static information.
        @param filepath: Path to the file to be analyzed.
        @return: results dict or None
        """

        results = {}
        vba = False
        if HAVE_OLETOOLS:
            if is_rtf(filepath):
                try:
                    with open(filepath, "rb") as f:
                        temp_results = self._parse_rtf(f.read())
                    if temp_results:
                        results["office_rtf"] = temp_results
                except Exception as e:
                    log.error(e, exc_info=True)
            else:
                try:
                    vba = VBA_Parser(filepath)
                except Exception:
                    return results
        else:
            return results

        officeresults = {}

        try:
            # extract DDE
            dde = extract_dde(filepath)
            if dde:
                results["office_dde"] = convert_to_printable(dde)
        except csv_error:
            pass
        except AttributeError:
            log.warning("OleFile library bug: AttributeError! fix: pip3 install -U olefile")
        except Exception as e:
            log.error(e, exc_info=True)

        metares = officeresults["Metadata"] = {}
        macro_folder = os.path.join(CUCKOO_ROOT, "storage", "analyses", self.task_id, "macros")
        if olefile.isOleFile(filepath):
            ole = olefile.OleFileIO(filepath)
            meta = ole.get_metadata()
            # must be left this way or we won't see the results
            officeresults["Metadata"] = self._get_meta(meta)
            metares = officeresults["Metadata"]
            if metares.get("SummaryInformation", {}).get("create_time", ""):
                metares["SummaryInformation"]["create_time"] = metares["SummaryInformation"]["create_time"]
            if metares.get("SummaryInformation", {}).get("last_saved_time", ""):
                metares["SummaryInformation"]["last_saved_time"] = metares["SummaryInformation"]["last_saved_time"]
            ole.close()
        else:
            try:
                officeresults["Metadata"] = self._get_xml_meta(filepath)
                metares = officeresults["Metadata"]
            except KeyError:
                pass

        if vba and vba.detect_vba_macros():
            metares["HasMacros"] = "Yes"
            macrores = officeresults["Macro"] = {}
            macrores["Code"] = {}
            macrores["info"] = {}
            ctr = 0
            # Create IOC and category vars. We do this before processing the
            # macro(s) to avoid overwriting data when there are multiple
            # macros in a single file.
            macrores["Analysis"] = {}
            macrores["Analysis"]["AutoExec"] = []
            macrores["Analysis"]["Suspicious"] = []
            macrores["Analysis"]["IOCs"] = []
            macrores["Analysis"]["HexStrings"] = []
            try:
                for (_, _, vba_filename, vba_code) in vba.extract_macros():
                    vba_code = filter_vba(vba_code)
                    if vba_code.strip() != "":
                        # Handle all macros
                        ctr += 1
                        outputname = f"Macro{ctr}"
                        macrores["Code"][outputname] = []
                        macrores["Code"][outputname].append((convert_to_printable(vba_filename), convert_to_printable(vba_code)))
                        autoexec = detect_autoexec(vba_code)
                        if not os.path.exists(macro_folder):
                            os.makedirs(macro_folder)
                        macro_file = os.path.join(macro_folder, outputname)
                        with open(macro_file, "w") as f:
                            f.write(convert_to_printable(vba_code))
                        macrores["info"][outputname] = {}
                        macrores["info"][outputname]["yara_macro"] = File(macro_file).get_yara(category="macro")
                        macrores["info"][outputname]["yara_macro"].extend(File(macro_file).get_yara(category="CAPE"))

                        suspicious = detect_suspicious(vba_code)
                        iocs = False
                        try:
                            iocs = vbadeobf.parse_macro(vba_code)
                        except Exception as e:
                            log.error(e, exc_info=True)
                        hex_strs = detect_hex_strings(vba_code)
                        if autoexec:
                            for keyword, description in autoexec:
                                macrores["Analysis"]["AutoExec"].append((keyword.replace(".", "_"), description))
                        if suspicious:
                            for keyword, description in suspicious:
                                macrores["Analysis"]["Suspicious"].append((keyword.replace(".", "_"), description))
                        if iocs:
                            for pattern, match in iocs:
                                macrores["Analysis"]["IOCs"].append((pattern, match))
                        if hex_strs:
                            for encoded, decoded in hex_strs:
                                macrores["Analysis"]["HexStrings"].append((encoded, convert_to_printable(decoded)))
            except (AssertionError, UnexpectedDataError) as e:
                log.warning(("Macros in static.py", e))
            # Delete and keys which had no results. Otherwise we pollute the
            # Django interface with null data.
            if macrores["Analysis"]["AutoExec"] == []:
                del macrores["Analysis"]["AutoExec"]
            if macrores["Analysis"]["Suspicious"] == []:
                del macrores["Analysis"]["Suspicious"]
            if macrores["Analysis"]["IOCs"] == []:
                del macrores["Analysis"]["IOCs"]
            if macrores["Analysis"]["HexStrings"] == []:
                del macrores["Analysis"]["HexStrings"]

            if HAVE_VBA2GRAPH:
                vba2graph_func(filepath, self.task_id, self.sha256)

        else:
            metares["HasMacros"] = "No"

        oleid = OleID(filepath)
        indicators = oleid.check()
        for indicator in indicators:
            if indicator.name == "Word Document" and indicator.value:
                metares["DocumentType"] = indicator.name
            if indicator.name == "Excel Workbook" and indicator.value:
                metares["DocumentType"] = indicator.name
            if indicator.name == "PowerPoint Presentation" and indicator.value:
                metares["DocumentType"] = indicator.name

        if HAVE_XLM_DEOBF:
            tmp_xlmmacro = xlmdeobfuscate(filepath, self.task_id, self.options.get("password", ""))
            if tmp_xlmmacro:
                officeresults.setdefault("XLMMacroDeobfuscator", tmp_xlmmacro)

        return officeresults

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None
        results = self._parse(self.file_path)
        return results
