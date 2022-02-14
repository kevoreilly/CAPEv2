# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import, print_function
import base64
import ctypes
import hashlib
import json
import logging
import os
import struct
from datetime import datetime
from subprocess import PIPE, Popen

import requests

import lib.cuckoo.common.integrations.vbadeobf as vbadeobf
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.cape_utils import generic_file_extractors
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.integrations.peepdf import peepdf_parse
from lib.cuckoo.common.objects import File, IsPEImage
from lib.cuckoo.common.pdftools.pdfid import PDFiD, PDFiD2JSON
from lib.cuckoo.common.structures import LnkEntry, LnkHeader
from lib.cuckoo.common.utils import convert_to_printable, get_options, store_temp_file

try:
    import re2 as re
except ImportError:
    import re

try:
    import bs4

    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

try:
    import magic

    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False

try:
    import pefile

    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

try:
    from whois import whois

    HAVE_WHOIS = True
except Exception:
    HAVE_WHOIS = False

try:
    import olefile

    HAVE_OLEFILE = True
except ImportError:
    HAVE_OLEFILE = False
    print("Missed olefile dependency: pip3 install olefile")

try:
    from oletools import oleobj
    from oletools.msodde import process_file as extract_dde
    from oletools.oleid import OleID
    from oletools.olevba import UnexpectedDataError, VBA_Parser, detect_autoexec, detect_hex_strings, detect_suspicious, filter_vba
    from oletools.rtfobj import RtfObjParser, is_rtf

    HAVE_OLETOOLS = True
except ImportError:
    print("Missed oletools dependency: pip3 install oletools")
    HAVE_OLETOOLS = False

try:
    from elftools.common.exceptions import ELFError
    from elftools.elf.constants import E_FLAGS
    from elftools.elf.descriptions import (
        describe_dyn_tag,
        describe_e_machine,
        describe_e_type,
        describe_e_version_numeric,
        describe_ei_class,
        describe_ei_data,
        describe_ei_osabi,
        describe_ei_version,
        describe_note,
        describe_p_flags,
        describe_p_type,
        describe_reloc_type,
        describe_sh_type,
        describe_symbol_bind,
        describe_symbol_type,
    )
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile
    from elftools.elf.enums import ENUM_D_TAG
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.segments import NoteSegment
except ImportError:
    ELFFile = False

processing_conf = Config("processing")

HAVE_FLARE_CAPA = False
# required to not load not enabled dependencies
if processing_conf.flare_capa.enabled and not processing_conf.flare_capa.on_demand:
    from lib.cuckoo.common.integrations.capa import HAVE_FLARE_CAPA, flare_capa_details

HAVE_VBA2GRAPH = False
if not processing_conf.vba2graph.on_demand:
    from lib.cuckoo.common.integrations.vba2graph import HAVE_VBA2GRAPH, vba2graph_func

HAVE_XLM_DEOBF = False
if not processing_conf.xlsdeobf.on_demand:
    from lib.cuckoo.common.integrations.XLMMacroDeobfuscator import HAVE_XLM_DEOBF, xlmdeobfuscate

log = logging.getLogger(__name__)


# Partially taken from
# http://malwarecookbook.googlecode.com/svn/trunk/3/8/pescanner.py


def _get_filetype(data):
    """Gets filetype, uses libmagic if available.
    @param data: data to be analyzed.
    @return: file type or None.
    """
    if not HAVE_MAGIC:
        return None

    try:
        ms = magic.open(magic.MAGIC_SYMLINK)
        ms.load()
        file_type = ms.buffer(data)
    except Exception:
        try:
            file_type = magic.from_buffer(data)
        except Exception:
            return None
    finally:
        try:
            ms.close()
        except Exception:
            pass

    return file_type


class DotNETExecutable(object):
    """.NET analysis"""

    def __init__(self, file_path, results):
        self.file_path = file_path
        self.results = results

    def add_statistic(self, name, field, value):
        self.results["statistics"]["processing"].append(
            {
                "name": name,
                field: value,
            }
        )

    def _get_custom_attrs(self):
        try:
            ret = []
            output = (
                Popen(["/usr/bin/monodis", "--customattr", self.file_path], stdout=PIPE, universal_newlines=True)
                .stdout.read()
                .split("\n")
            )
            for line in output[1:]:
                splitline = line.split()
                if not splitline or len(splitline) < 7:
                    continue
                typeval = splitline[1].rstrip(":")
                nameval = splitline[6].split("::", 1)[0]
                if "(string)" not in splitline[6]:
                    continue
                rem = " ".join(splitline[7:])
                startidx = rem.find('["')
                if startidx < 0:
                    continue
                endidx = rem.rfind('"]')
                # also ignore empty strings
                if endidx <= 2:
                    continue
                valueval = rem[startidx + 2 : endidx - 2]
                item = {}
                item["type"] = convert_to_printable(typeval)
                item["name"] = convert_to_printable(nameval)
                item["value"] = convert_to_printable(valueval)
                ret.append(item)
            return ret
        except Exception as e:
            log.error(e, exc_info=True)
            return None

    def _get_assembly_refs(self):
        try:
            ret = []
            output = (
                Popen(["/usr/bin/monodis", "--assemblyref", self.file_path], stdout=PIPE, universal_newlines=True)
                .stdout.read()
                .split("\n")
            )
            for idx, line in enumerate(output):
                splitline = line.split("Version=")
                if len(splitline) < 2:
                    continue
                verval = splitline[1]
                splitline = output[idx + 1].split("Name=")
                if len(splitline) < 2:
                    continue
                nameval = splitline[1]
                item = {}
                item["name"] = convert_to_printable(nameval)
                item["version"] = convert_to_printable(verval)
                ret.append(item)
            return ret

        except Exception as e:
            log.error(e, exc_info=True)
            return None

    def _get_assembly_info(self):
        try:
            ret = {}
            output = (
                Popen(["/usr/bin/monodis", "--assembly", self.file_path], stdout=PIPE, universal_newlines=True)
                .stdout.read()
                .split("\n")
            )
            for line in output:
                if line.startswith("Name:"):
                    ret["name"] = convert_to_printable(line[5:].strip())
                if line.startswith("Version:"):
                    ret["version"] = convert_to_printable(line[8:].strip())
            return ret
        except Exception as e:
            log.error(e, exc_info=True)
            return None

    def _get_type_refs(self):
        try:
            ret = []
            output = (
                Popen(["/usr/bin/monodis", "--typeref", self.file_path], stdout=PIPE, universal_newlines=True)
                .stdout.read()
                .split("\n")
            )
            for line in output[1:]:
                restline = "".join(line.split(":")[1:])
                restsplit = restline.split("]")
                asmname = restsplit[0][2:]
                typename = "".join(restsplit[1:])
                if asmname and typename:
                    item = {}
                    item["assembly"] = convert_to_printable(asmname)
                    item["typename"] = convert_to_printable(typename)
                    ret.append(item)
            return ret

        except Exception as e:
            log.error(e, exc_info=True)
            return None

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None

        results = {}

        try:
            results["dotnet"] = {}
            pretime = datetime.now()
            results["dotnet"]["typerefs"] = self._get_type_refs()
            results["dotnet"]["assemblyrefs"] = self._get_assembly_refs()
            results["dotnet"]["assemblyinfo"] = self._get_assembly_info()
            results["dotnet"]["customattrs"] = self._get_custom_attrs()
            posttime = datetime.now()
            timediff = posttime - pretime
            self.add_statistic("static_dotnet", "time", float(f"{timediff.seconds}.{timediff.microseconds // 1000:03d}"))
            return results
        except Exception as e:
            log.error(e, exc_info=True)
            return None


class PortableExecutable(object):
    """PE analysis."""

    def __init__(self, file_path, results):
        """@param file_path: file path."""
        self.file_path = file_path
        self.pe = None
        self.results = results

    def add_statistic(self, name, field, value):
        self.results["statistics"]["processing"].append({"name": name, field: value})

    def add_statistic_tmp(self, name, field, pretime):
        posttime = datetime.now()
        timediff = posttime - pretime
        value = float(f"{timediff.seconds}.{timediff.microseconds // 1000:03d}")

        if name not in self.results["temp_processing_stats"]:
            self.results["temp_processing_stats"][name] = {}

        # To be able to add yara/capa and others time summary over all processing modules
        if field in self.results["temp_processing_stats"][name]:
            self.results["temp_processing_stats"][name][field] += value
        else:
            self.results["temp_processing_stats"][name][field] = value

    def _get_guest_digital_signers(self):
        retdata = {}
        cert_data = {}
        cert_info = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.results["info"]["id"]), "aux", "DigiSig.json")

        if os.path.exists(cert_info):
            with open(cert_info, "r") as cert_file:
                buf = cert_file.read()
            if buf:
                cert_data = json.loads(buf)

        if cert_data:
            retdata = {
                "aux_sha1": cert_data["sha1"],
                "aux_timestamp": cert_data["timestamp"],
                "aux_valid": cert_data["valid"],
                "aux_error": cert_data["error"],
                "aux_error_desc": cert_data["error_desc"],
                "aux_signers": cert_data["signers"],
            }

        return retdata

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            log.debug("File doesn't exist anymore")
            return {}

        # Advanced check if is real PE
        if not IsPEImage(open(self.file_path, "rb").read()):
            return {}

        results = {}
        peresults = results["pe"] = {}
        results["pe"], _ = File(self.file_path).get_all()
        peresults["guest_signers"] = self._get_guest_digital_signers()
        if HAVE_FLARE_CAPA:
            pretime = datetime.now()
            capa_details = flare_capa_details(self.file_path, "static")
            if capa_details:
                results["flare_capa"] = capa_details
            self.add_statistic_tmp("flare_capa", "time", pretime)

        return results


class PDF(object):
    """PDF Analysis."""

    def __init__(self, file_path):
        self.file_path = file_path

    def _parse(self, filepath):
        """Parses the PDF for static information.
        @param filepath: Path to file to be analyzed.
        @return: results dict or None.
        """
        # Load the PDF with PDFiD and convert it to JSON for processing
        pdf_data = PDFiD(filepath, False, True)
        pdf_json = PDFiD2JSON(pdf_data, True)
        pdfid_data = json.loads(pdf_json)[0]

        info = {}
        info["PDF Header"] = pdfid_data["pdfid"]["header"]
        info["Total Entropy"] = pdfid_data["pdfid"]["totalEntropy"]
        info["Entropy In Streams"] = pdfid_data["pdfid"]["streamEntropy"]
        info["Entropy Out Streams"] = pdfid_data["pdfid"]["nonStreamEntropy"]
        info["Count %% EOF"] = pdfid_data["pdfid"]["countEof"]
        info["Data After EOF"] = pdfid_data["pdfid"]["countChatAfterLastEof"]
        # Note, PDFiD doesn't interpret some dates properly, specifically it doesn't
        # seem to be able to properly represent time zones that involve fractions of
        # an hour
        dates = pdfid_data["pdfid"]["dates"]["date"]

        # Get keywords, counts and format.
        keywords = {}
        for keyword in pdfid_data["pdfid"]["keywords"]["keyword"]:
            keywords[str(keyword["name"])] = keyword["count"]

        result = {}
        pdfresult = result["pdf"] = {}
        pdfresult["Info"] = info
        pdfresult["Dates"] = dates
        pdfresult["Keywords"] = keywords

        pdfresult = peepdf_parse(self.file_path, pdfresult)

        return result

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None
        log.debug("Starting to load PDF")
        results = self._parse(self.file_path)
        return results


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

    def __init__(self, file_path, results, options):
        self.file_path = file_path
        self.results = results
        self.options = get_options(options)

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

    def _parse_rtf(self, data):
        results = {}
        rtfp = RtfObjParser(data)
        rtfp.parse()
        save_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.results["info"]["id"]), "rtf_objects")
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

        log.debug(results)
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
                    temp_results = self._parse_rtf(open(filepath, "rb").read())
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

        officeresults = results["office"] = {}

        try:
            # extract DDE
            dde = extract_dde(filepath)
            if dde:
                results["office_dde"] = convert_to_printable(dde)
        except AttributeError:
            log.warning("OleFile library bug: AttributeError! fix: pip3 install -U olefile")
        except Exception as e:
            log.error(e, exc_info=True)

        metares = officeresults["Metadata"] = {}
        macro_folder = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.results["info"]["id"]), "macros")
        # The bulk of the metadata checks are in the OLE Structures
        # So don't check if we're dealing with XML.
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
                vba2graph_func(filepath, str(self.results["info"]["id"]), self.results["target"]["file"]["sha256"])

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
            tmp_xlmmacro = xlmdeobfuscate(filepath, self.results["info"]["id"], self.options.get("password", ""))
            if tmp_xlmmacro:
                results["office"].setdefault("XLMMacroDeobfuscator", tmp_xlmmacro)

        return results

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None
        results = self._parse(self.file_path)
        return results


class LnkShortcut(object):
    signature = [0x4C, 0x00, 0x00, 0x00]
    guid = [
        0x01,
        0x14,
        0x02,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xC0,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x46,
    ]
    flags = [
        "shellidlist",
        "references",
        "description",
        "relapath",
        "workingdir",
        "cmdline",
        "icon",
    ]
    attrs = [
        "readonly",
        "hidden",
        "system",
        None,
        "directory",
        "archive",
        "ntfs_efs",
        "normal",
        "temporary",
        "sparse",
        "reparse",
        "compressed",
        "offline",
        "not_indexed",
        "encrypted",
    ]

    def __init__(self, filepath=None):
        self.filepath = filepath

    def read_uint16(self, offset):
        return struct.unpack("H", self.buf[offset : offset + 2])[0]

    def read_uint32(self, offset):
        return struct.unpack("I", self.buf[offset : offset + 4])[0]

    def read_stringz(self, offset):
        return self.buf[offset : self.buf.index(b"\x00", offset)]

    def read_string16(self, offset):
        length = self.read_uint16(offset) * 2
        ret = self.buf[offset + 2 : offset + 2 + length].decode("utf16")
        return offset + 2 + length, ret

    def run(self):
        buf = self.buf = open(self.filepath, "rb").read()
        if len(buf) < ctypes.sizeof(LnkHeader):
            log.warning("Provided .lnk file is corrupted or incomplete")
            return

        header = LnkHeader.from_buffer_copy(buf[: ctypes.sizeof(LnkHeader)])
        if header.signature[:] != self.signature:
            return

        if header.guid[:] != self.guid:
            return

        ret = {"flags": {}, "attrs": []}

        for x in range(7):
            ret["flags"][self.flags[x]] = bool(header.flags & (1 << x))

        for x in range(14):
            if header.attrs & (1 << x):
                ret["attrs"].append(self.attrs[x])

        offset = 78 + self.read_uint16(76)
        if len(buf) < offset + 28:
            log.warning("Provided .lnk file is corrupted or incomplete")
            return

        off = LnkEntry.from_buffer_copy(buf[offset : offset + 28])

        # Local volume.
        if off.volume_flags & 1:
            ret["basepath"] = self.read_stringz(offset + off.base_path)
        # Network volume.
        else:
            ret["net_share"] = self.read_stringz(offset + off.net_volume + 20)
            network_drive = self.read_uint32(offset + off.net_volume + 12)
            if network_drive:
                ret["network_drive"] = self.read_stringz(offset + network_drive)

        ret["remaining_path"] = self.read_stringz(offset + off.path_remainder)

        extra = offset + off.length
        if ret["flags"]["description"]:
            extra, ret["description"] = self.read_string16(extra)
        if ret["flags"]["relapath"]:
            extra, ret["relapath"] = self.read_string16(extra)
        if ret["flags"]["workingdir"]:
            extra, ret["workingdir"] = self.read_string16(extra)
        if ret["flags"]["cmdline"]:
            extra, ret["cmdline"] = self.read_string16(extra)
        if ret["flags"]["icon"]:
            extra, ret["icon"] = self.read_string16(extra)
        return ret


class ELF(object):
    def __init__(self, file_path):
        self.file_path = file_path
        self.elf = None
        self.result = {}

    def run(self):
        try:
            self.elf = ELFFile(open(self.file_path, "rb"))
            self.result["file_header"] = self._get_file_header()
            self.result["section_headers"] = self._get_section_headers()
            self.result["program_headers"] = self._get_program_headers()
            self.result["dynamic_tags"] = self._get_dynamic_tags()
            self.result["symbol_tables"] = self._get_symbol_tables()
            self.result["relocations"] = self._get_relocations()
            self.result["notes"] = self._get_notes()
            # TODO: add library name per import (see #807)
        except ELFError as e:
            if e.message != "Magic number does not match":
                raise

        return self.result

    def _get_file_header(self):
        return {
            "magic": convert_to_printable(self.elf.e_ident_raw[:4]),
            "class": describe_ei_class(self.elf.header.e_ident["EI_CLASS"]),
            "data": describe_ei_data(self.elf.header.e_ident["EI_DATA"]),
            "ei_version": describe_ei_version(self.elf.header.e_ident["EI_VERSION"]),
            "os_abi": describe_ei_osabi(self.elf.header.e_ident["EI_OSABI"]),
            "abi_version": self.elf.header.e_ident["EI_ABIVERSION"],
            "type": describe_e_type(self.elf.header["e_type"]),
            "machine": describe_e_machine(self.elf.header["e_machine"]),
            "version": describe_e_version_numeric(self.elf.header["e_version"]),
            "entry_point_address": self._print_addr(self.elf.header["e_entry"]),
            "start_of_program_headers": self.elf.header["e_phoff"],
            "start_of_section_headers": self.elf.header["e_shoff"],
            "flags": f"{self._print_addr(self.elf.header['e_flags'])}{self._decode_flags(self.elf.header['e_flags'])}",
            "size_of_this_header": self.elf.header["e_ehsize"],
            "size_of_program_headers": self.elf.header["e_phentsize"],
            "number_of_program_headers": self.elf.header["e_phnum"],
            "size_of_section_headers": self.elf.header["e_shentsize"],
            "number_of_section_headers": self.elf.header["e_shnum"],
            "section_header_string_table_index": self.elf.header["e_shstrndx"],
        }

    def _get_section_headers(self):
        section_headers = []
        for section in self.elf.iter_sections():
            section_headers.append(
                {
                    "name": section.name,
                    "type": describe_sh_type(section["sh_type"]),
                    "addr": self._print_addr(section["sh_addr"]),
                    "size": section["sh_size"],
                }
            )
        return section_headers

    def _get_program_headers(self):
        program_headers = []
        for segment in self.elf.iter_segments():
            program_headers.append(
                {
                    "type": describe_p_type(segment["p_type"]),
                    "addr": self._print_addr(segment["p_vaddr"]),
                    "flags": describe_p_flags(segment["p_flags"]).strip(),
                    "size": segment["p_memsz"],
                }
            )
        return program_headers

    def _get_dynamic_tags(self):
        dynamic_tags = []
        for section in self.elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                dynamic_tags.append(
                    {
                        "tag": self._print_addr(ENUM_D_TAG.get(tag.entry.d_tag, tag.entry.d_tag)),
                        "type": str(tag.entry.d_tag)[3:],
                        "value": self._parse_tag(tag),
                    }
                )

        return dynamic_tags

    def _get_symbol_tables(self):
        symbol_tables = []
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for nsym, symbol in enumerate(section.iter_symbols()):
                symbol_tables.append(
                    {
                        "value": self._print_addr(symbol["st_value"]),
                        "type": describe_symbol_type(symbol["st_info"]["type"]),
                        "bind": describe_symbol_bind(symbol["st_info"]["bind"]),
                        "ndx_name": symbol.name,
                    }
                )
        return symbol_tables

    def _get_relocations(self):
        relocations = []
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            section_relocations = []
            for rel in section.iter_relocations():
                relocation = {
                    "offset": self._print_addr(rel["r_offset"]),
                    "info": self._print_addr(rel["r_info"]),
                    "type": describe_reloc_type(rel["r_info_type"], self.elf),
                    "value": "",
                    "name": "",
                }

                if rel["r_info_sym"] != 0:
                    symtable = self.elf.get_section(section["sh_link"])
                    symbol = symtable.get_symbol(rel["r_info_sym"])
                    # Some symbols have zero "st_name", so instead use
                    # the name of the section they point at
                    if symbol["st_name"] == 0:
                        symsec = self.elf.get_section(symbol["st_shndx"])
                        symbol_name = symsec.name
                    else:
                        symbol_name = symbol.name

                    relocation["value"] = self._print_addr(symbol["st_value"])
                    relocation["name"] = symbol_name

                if relocation not in section_relocations:
                    section_relocations.append(relocation)

            relocations.append(
                {
                    "name": section.name,
                    "entries": section_relocations,
                }
            )
        return relocations

    def _get_notes(self):
        notes = []
        for segment in self.elf.iter_segments():
            if not isinstance(segment, NoteSegment):
                continue
            for note in segment.iter_notes():
                notes.append(
                    {
                        "owner": note["n_name"],
                        "size": self._print_addr(note["n_descsz"]),
                        "note": describe_note(note),
                        "name": note["n_name"],
                    }
                )
        return notes

    def _print_addr(self, addr):
        fmt = f"0x{addr:08x}" if self.elf.elfclass == 32 else f"0x{addr:016x}"
        return fmt

    def _decode_flags(self, flags):
        description = ""
        if self.elf["e_machine"] == "EM_ARM":
            if flags & E_FLAGS.EF_ARM_HASENTRY:
                description = ", has entry point"

            version = flags & E_FLAGS.EF_ARM_EABIMASK
            if version == E_FLAGS.EF_ARM_EABI_VER5:
                description = ", Version5 EABI"
        elif self.elf["e_machine"] == "EM_MIPS":
            if flags & E_FLAGS.EF_MIPS_NOREORDER:
                description = ", noreorder"
            if flags & E_FLAGS.EF_MIPS_CPIC:
                description = ", cpic"
            if not (flags & E_FLAGS.EF_MIPS_ABI2) and not (flags & E_FLAGS.EF_MIPS_ABI_ON32):
                description = ", o32"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_1:
                description = ", mips1"

        return description

    def _parse_tag(self, tag):
        if tag.entry.d_tag == "DT_NEEDED":
            parsed = f"Shared library: [{tag.needed}]"
        elif tag.entry.d_tag == "DT_RPATH":
            parsed = f"Library rpath: [{tag.rpath}]"
        elif tag.entry.d_tag == "DT_RUNPATH":
            parsed = f"Library runpath: [{tag.runpath}]"
        elif tag.entry.d_tag == "DT_SONAME":
            parsed = f"Library soname: [{tag.soname}]"
        elif isinstance(tag.entry.d_tag, str) and tag.entry.d_tag.endswith(("SZ", "ENT")):
            parsed = f"{tag['d_val']} (bytes)"
        elif isinstance(tag.entry.d_tag, str) and tag.entry.d_tag.endswith(("NUM", "COUNT")):
            parsed = str(tag["d_val"])
        elif tag.entry.d_tag == "DT_PLTREL":
            s = describe_dyn_tag(tag.entry.d_val)
            if s.startswith("DT_"):
                s = s[3:]
            parsed = s
        else:
            parsed = self._print_addr(tag["d_val"])

        return parsed


'''
class HwpDocument(object):
    """Static analysis of HWP documents."""

    def __init__(self, filepath, results):
        self.filepath = filepath
        self.files = {}
        #self.ex = ExtractManager.for_task(task_id)

    def unpack_hwp(self):
        """Unpacks ole-based zip files."""
        ole = olefile.OleFileIO(self.filepath)
        streams = ole.listdir()
        for stream in streams:
            stream_name = '/'.join(stream)
	    content = ole.openstream(stream).read()
	    try:
	        stream_content = zlib.decompress(ole.openstream(stream).read(), -15)
                self.files[stream_name] = stream_content
	    except Exception as e:
            log.error(e, exc_info=True)
        ole.close()

    def extract_eps(self):
        """Extract some information from Encapsulated Post Script files."""
        ret = []
        for filename, content in self.files.items():
            if filename.lower().endswith(".eps") or filename.lower().endswith(".ps"):
                ret.append(content)
        return ret

    def run(self):
        self.unpack_hwp()

        self.ex.peek_office(self.files)

        return {
            "eps": self.extract_eps()
        }
'''


class Java(object):
    """Java Static Analysis"""

    def __init__(self, file_path, decomp_jar):
        self.file_path = file_path
        self.decomp_jar = decomp_jar

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None

        results = {}

        results["java"] = {}

        if self.decomp_jar:
            f = open(self.file_path, "rb")
            data = f.read()
            f.close()
            jar_file = store_temp_file(data, "decompile.jar")

            try:
                if self.decomp_jar.endswith(".jar"):
                    p = Popen(["java", "-jar", self.decomp_jar, jar_file], stdout=PIPE)
                else:
                    p = Popen([self.decomp_jar, jar_file], stdout=PIPE)
                results["java"]["decompiled"] = convert_to_printable(p.stdout.read())
            except Exception as e:
                log.error(e, exc_info=True)
                pass

            try:
                os.unlink(jar_file)
            except Exception:
                pass

        return results


class URL(object):
    """URL 'Static' Analysis"""

    def __init__(self, url):
        self.url = url
        p = r"^(?:https?:\/\/)?(?:www\.)?(?P<domain>[^:\/\n]+)"
        dcheck = re.match(p, self.url)
        if dcheck:
            self.domain = dcheck.group("domain")
            # Work around a bug where a "." can tail a url target if
            # someone accidentally appends one during submission
            while self.domain.endswith("."):
                self.domain = self.domain[:-1]
        else:
            self.domain = ""

    def parse_json_in_javascript(self, data=str(), ignore_nest_level=0):
        nest_count = 0 - ignore_nest_level
        string_buf = str()
        json_buf = []
        json_data = []
        for character in data:
            if character == "{":
                nest_count += 1
            if nest_count > 0:
                string_buf += character
            if character == "}":
                nest_count -= 1
            if nest_count == 0 and len(string_buf):
                json_buf.append(string_buf)
                string_buf = str()

        if json_buf:
            for data in json_buf:
                if len(data) > 4:
                    json_data.append(json.loads(data))
            return json_data

        return []

    def run(self):
        results = {}
        if self.domain:
            try:
                w = whois(self.domain)
                results["url"] = {}
                # Create static fields if they don't exist, EG if the WHOIS
                # data is stale.
                fields = [
                    "updated_date",
                    "status",
                    "name",
                    "city",
                    "expiration_date",
                    "zipcode",
                    "domain_name",
                    "country",
                    "whois_server",
                    "state",
                    "registrar",
                    "referral_url",
                    "address",
                    "name_servers",
                    "org",
                    "creation_date",
                    "emails",
                ]
                for field in fields:
                    if field not in list(w.keys()) or not w[field]:
                        w[field] = ["None"]
            except Exception:
                # No WHOIS data returned
                log.warning("No WHOIS data for domain: %s", self.domain)
                return results

            # These can be a list or string, just make them all lists
            for key in w.keys():
                buf = []
                # Handle and format dates
                if "_date" in key:
                    if isinstance(w[key], list):
                        buf = [str(dt).replace("T", " ").split(".", 1)[0] for dt in w[key]]
                    else:
                        buf = [str(w[key]).replace("T", " ").split(".", 1)[0]]
                else:
                    if isinstance(w[key], list):
                        continue
                    else:
                        buf = [w[key]]
                w[key] = buf

            output = (
                "Name: {0}\nCountry: {1}\nState: {2}\nCity: {3}\n"
                "ZIP Code: {4}\nAddress: {5}\n\nOrginization: {6}\n"
                "Domain Name(s):\n    {7}\nCreation Date:\n    {8}\n"
                "Updated Date:\n    {9}\nExpiration Date:\n    {10}\n"
                "Email(s):\n    {11}\n\nRegistrar(s):\n    {12}\nName "
                "Server(s):\n    {13}\nReferral URL(s):\n    {14}"
            )
            output = output.format(
                w["name"][0],
                w["country"][0],
                w["state"][0],
                w["city"][0],
                w["zipcode"][0],
                w["address"][0],
                w["org"][0],
                "\n    ".join(w["domain_name"]),
                "\n    ".join(w["creation_date"]),
                "\n    ".join(w["updated_date"]),
                "\n    ".join(w["expiration_date"]),
                "\n    ".join(w["emails"]),
                "\n    ".join(w["registrar"]),
                "\n    ".join(w["name_servers"]),
                "\n    ".join(w["referral_url"]),
            )
            results["url"]["whois"] = output

        if self.domain == "bit.ly":
            resp = requests.get(f"{self.url}+")
            soup = bs4.BeautifulSoup(resp.text, "html.parser")
            output = []
            for script in [x.extract() for x in soup.find_all("script")]:
                if script.contents:
                    content = script.contents[0]
                    if "long_url_no_protocol" in content:
                        output = self.parse_json_in_javascript(content, 1)

            if output:
                results["url"]["bitly"] = {k: v for d in output for k, v in d.iteritems()}
                newtime = datetime.fromtimestamp(int(results["url"]["bitly"]["created_at"]))
                results["url"]["bitly"]["created_at"] = f"{newtime.strftime('%Y-%m-%d %H:%M:%S')} GMT"

        return results


class EncodedScriptFile(object):
    """Deobfuscates and interprets Windows Script Files."""

    encoding = [
        1,
        2,
        0,
        1,
        2,
        0,
        2,
        0,
        0,
        2,
        0,
        2,
        1,
        0,
        2,
        0,
        1,
        0,
        2,
        0,
        1,
        1,
        2,
        0,
        0,
        2,
        1,
        0,
        2,
        0,
        0,
        2,
        1,
        1,
        0,
        2,
        0,
        2,
        0,
        1,
        0,
        1,
        1,
        2,
        0,
        1,
        0,
        2,
        1,
        0,
        2,
        0,
        1,
        1,
        2,
        0,
        0,
        1,
        1,
        2,
        0,
        1,
        0,
        2,
    ]

    lookup = [
        [
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x7B,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            0x18,
            0x19,
            0x1A,
            0x1B,
            0x1C,
            0x1D,
            0x1E,
            0x1F,
            0x32,
            0x30,
            0x21,
            0x29,
            0x5B,
            0x38,
            0x33,
            0x3D,
            0x58,
            0x3A,
            0x35,
            0x65,
            0x39,
            0x5C,
            0x56,
            0x73,
            0x66,
            0x4E,
            0x45,
            0x6B,
            0x62,
            0x59,
            0x78,
            0x5E,
            0x7D,
            0x4A,
            0x6D,
            0x71,
            0x00,
            0x60,
            0x00,
            0x53,
            0x00,
            0x42,
            0x27,
            0x48,
            0x72,
            0x75,
            0x31,
            0x37,
            0x4D,
            0x52,
            0x22,
            0x54,
            0x6A,
            0x47,
            0x64,
            0x2D,
            0x20,
            0x7F,
            0x2E,
            0x4C,
            0x5D,
            0x7E,
            0x6C,
            0x6F,
            0x79,
            0x74,
            0x43,
            0x26,
            0x76,
            0x25,
            0x24,
            0x2B,
            0x28,
            0x23,
            0x41,
            0x34,
            0x09,
            0x2A,
            0x44,
            0x3F,
            0x77,
            0x3B,
            0x55,
            0x69,
            0x61,
            0x63,
            0x50,
            0x67,
            0x51,
            0x49,
            0x4F,
            0x46,
            0x68,
            0x7C,
            0x36,
            0x70,
            0x6E,
            0x7A,
            0x2F,
            0x5F,
            0x4B,
            0x5A,
            0x2C,
            0x57,
        ],
        [
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x57,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            0x18,
            0x19,
            0x1A,
            0x1B,
            0x1C,
            0x1D,
            0x1E,
            0x1F,
            0x2E,
            0x47,
            0x7A,
            0x56,
            0x42,
            0x6A,
            0x2F,
            0x26,
            0x49,
            0x41,
            0x34,
            0x32,
            0x5B,
            0x76,
            0x72,
            0x43,
            0x38,
            0x39,
            0x70,
            0x45,
            0x68,
            0x71,
            0x4F,
            0x09,
            0x62,
            0x44,
            0x23,
            0x75,
            0x00,
            0x7E,
            0x00,
            0x5E,
            0x00,
            0x77,
            0x4A,
            0x61,
            0x5D,
            0x22,
            0x4B,
            0x6F,
            0x4E,
            0x3B,
            0x4C,
            0x50,
            0x67,
            0x2A,
            0x7D,
            0x74,
            0x54,
            0x2B,
            0x2D,
            0x2C,
            0x30,
            0x6E,
            0x6B,
            0x66,
            0x35,
            0x25,
            0x21,
            0x64,
            0x4D,
            0x52,
            0x63,
            0x3F,
            0x7B,
            0x78,
            0x29,
            0x28,
            0x73,
            0x59,
            0x33,
            0x7F,
            0x6D,
            0x55,
            0x53,
            0x7C,
            0x3A,
            0x5F,
            0x65,
            0x46,
            0x58,
            0x31,
            0x69,
            0x6C,
            0x5A,
            0x48,
            0x27,
            0x5C,
            0x3D,
            0x24,
            0x79,
            0x37,
            0x60,
            0x51,
            0x20,
            0x36,
        ],
        [
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x6E,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            0x18,
            0x19,
            0x1A,
            0x1B,
            0x1C,
            0x1D,
            0x1E,
            0x1F,
            0x2D,
            0x75,
            0x52,
            0x60,
            0x71,
            0x5E,
            0x49,
            0x5C,
            0x62,
            0x7D,
            0x29,
            0x36,
            0x20,
            0x7C,
            0x7A,
            0x7F,
            0x6B,
            0x63,
            0x33,
            0x2B,
            0x68,
            0x51,
            0x66,
            0x76,
            0x31,
            0x64,
            0x54,
            0x43,
            0x00,
            0x3A,
            0x00,
            0x7E,
            0x00,
            0x45,
            0x2C,
            0x2A,
            0x74,
            0x27,
            0x37,
            0x44,
            0x79,
            0x59,
            0x2F,
            0x6F,
            0x26,
            0x72,
            0x6A,
            0x39,
            0x7B,
            0x3F,
            0x38,
            0x77,
            0x67,
            0x53,
            0x47,
            0x34,
            0x78,
            0x5D,
            0x30,
            0x23,
            0x5A,
            0x5B,
            0x6C,
            0x48,
            0x55,
            0x70,
            0x69,
            0x2E,
            0x4C,
            0x21,
            0x24,
            0x4E,
            0x50,
            0x09,
            0x56,
            0x73,
            0x35,
            0x61,
            0x4B,
            0x58,
            0x3B,
            0x57,
            0x22,
            0x6D,
            0x4D,
            0x25,
            0x28,
            0x46,
            0x4A,
            0x32,
            0x41,
            0x3D,
            0x5F,
            0x4F,
            0x42,
            0x65,
        ],
    ]

    unescape = {
        "#": "\r",
        "&": "\n",
        "!": "<",
        "*": ">",
        "$": "@",
    }

    def __init__(self, filepath):
        self.filepath = filepath

    def run(self):
        results = {}
        try:
            source = open(self.filepath, "rb").read()
        except UnicodeDecodeError as e:
            return results
        source = self.decode(source)
        if not source:
            return results
        results["encscript"] = source[:65536]
        if len(source) > 65536:
            results["encscript"] += "\r\n<truncated>"
        return results

    def decode(self, source, start=b"#@~^", end=b"^#~@"):
        if start not in source or end not in source:
            return

        o = source.index(start) + len(start) + 8
        end = source.index(end) - 8
        c, m, r = bytes([]), 0, []

        while o < end:
            ch = source[o]
            if source[o] == 64:  # b"@":
                r.append(self.unescape.get(source[o + 1], b"?"))
                c += r[-1]
                o, m = o + 1, m + 1
            elif ch < 128:
                r.append(self.lookup[self.encoding[m % 64]][ch])
                c += r[-1]
                m += 1
            else:
                r.append(ch)
            o += 1

        if (c % 2 ** 32) != base64.b64decode(struct.unpack("=I", source[o : o + 4]))[0]:
            log.info("Invalid checksum for Encoded WSF file!")

        return b"".join(ch for ch in r).decode("latin-1")


class WindowsScriptFile(object):
    script_re = "<\\s*script\\s*.*>.*?<\\s*/\\s*script\\s*>"

    def __init__(self, filepath):
        self.filepath = filepath

    def run(self):
        results = {}
        ret = []
        source = open(self.filepath, "r").read()

        # Get rid of superfluous comments.
        source = re.sub("/\\*.*?\\*/", "", source, flags=re.S)

        for script in re.findall(self.script_re, source, re.I | re.S):
            try:
                x = bs4.BeautifulSoup(script, "html.parser")
                language = x.script.attrs.get("language", "").lower()
            except Exception:
                language = None

            # We can't rely on bs4 or any other HTML/XML parser to provide us
            # with the raw content of the xml tag as they decode html entities
            # and all that, leaving us with a corrupted string.
            source = re.match("<.*>(.*)</.*>$", script, re.S).group(0)

            # Decode JScript.Encode encoding.
            if language in ("jscript.encode", "vbscript.encode"):
                source = EncodedScriptFile(self.filepath).decode(source)

            if len(source) > 65536:
                source = f"{source[:65536]}\r\n<truncated>"

            ret.append(source)

        results["wsf"] = ret
        return results


class Static(Processing):
    """Static analysis."""

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        self.key = "static"
        static = {}

        if self.task["category"] == "file":
            package = self.results.get("info", {}).get("package", "")

            thetype = File(self.file_path).get_type()
            if not HAVE_OLETOOLS and "Zip archive data, at least v2.0" in thetype and package in ("doc", "ppt", "xls", "pub"):
                log.info("Missed dependencies: pip3 install oletools")

            if HAVE_PEFILE and ("PE32" in thetype or "MS-DOS executable" in thetype):
                static = PortableExecutable(self.file_path, self.results).run()
                if static and "Mono" in File(self.file_path).get_content_type():
                    static.update(DotNETExecutable(self.file_path, self.results).run())
            elif "PDF" in thetype or self.task["target"].endswith(".pdf"):
                static = PDF(self.file_path).run()
            elif HAVE_OLETOOLS and package in ("doc", "ppt", "xls", "pub"):
                static = Office(self.file_path, self.results, self.task["options"]).run()
            # elif HAVE_OLETOOLS and package in ("hwp", "hwp"):
            #    static = HwpDocument(self.file_path, self.results).run()
            elif "Java Jar" in thetype or self.task["target"].endswith(".jar"):
                decomp_jar = self.options.get("procyon_path")
                if decomp_jar and not os.path.exists(decomp_jar):
                    log.error("procyon_path specified in processing.conf but the file does not exist")
                static = Java(self.file_path, decomp_jar).run()
            # It's possible to fool libmagic into thinking our 2007+ file is a
            # zip. So until we have static analysis for zip files, we can use
            # oleid to fail us out silently, yeilding no static analysis
            # results for actual zip files.
            elif HAVE_OLETOOLS and "Zip archive data, at least v2.0" in thetype:
                static = Office(self.file_path, self.results, self.task["options"]).run()
            elif package == "wsf" or thetype == "XML document text" or self.task["target"].endswith(".wsf") or package == "hta":
                static = WindowsScriptFile(self.file_path).run()
            elif package == "js" or package == "vbs":
                static = EncodedScriptFile(self.file_path).run()
            elif package == "lnk":
                static["lnk"] = LnkShortcut(self.file_path).run()
            # elif self.file_path.endswith(".elf") or "ELF" in thetype:
            #    static["elf"] = ELF(self.file_path).run()
            #    static["keys"] = f.get_keys()

            # Allows to put execute file extractors/unpackers
            generic_file_extractors(self.file_path, self.dropped_path, thetype, static)
        elif self.task["category"] == "url":
            enabled_whois = self.options.get("whois", True)
            if HAVE_WHOIS and enabled_whois:
                static = URL(self.task["target"]).run()

        return static
