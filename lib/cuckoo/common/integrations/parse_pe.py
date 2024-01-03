# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import array
import base64
import binascii
import hashlib
import itertools
import json
import logging
import math
import struct
from contextlib import suppress
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Tuple

from PIL import Image

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.icon import PEGroupIconDir
from lib.cuckoo.common.path_utils import path_exists, path_read_file

try:
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    from cryptography.hazmat.primitives import hashes

    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
    print("Missed cryptography library: poetry install")

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
    import re2 as re
except ImportError:
    import re

process_cfg = Config("processing")

HAVE_USERDB = False
if process_cfg.CAPE.userdb_signature:
    try:
        import peutils

        userdb_path = Path(CUCKOO_ROOT, "data", "peutils", "UserDB.TXT")
        userdb_signatures = peutils.SignatureDatabase()
        if userdb_path.exists():
            userdb_signatures.load(userdb_path)
            HAVE_USERDB = True
    except (ImportError, AttributeError) as e:
        print(f"Failed to initialize peutils: {e}")


log = logging.getLogger(__name__)

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
OPTIONAL_HEADER_MAGIC_PE = 0x10B
OPTIONAL_HEADER_MAGIC_PE_PLUS = 0x20B
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
DOS_HEADER_LIMIT = 0x40
PE_HEADER_LIMIT = 0x200


def IsPEImage(buf: bytes, size: int = False) -> bool:
    if not buf:
        return False
    if not size:
        size = len(buf)
    if size < DOS_HEADER_LIMIT:
        return False
    dos_header = buf[:DOS_HEADER_LIMIT]
    nt_headers = None

    e_lfanew = False
    if len(dos_header[:64]) == 64:
        # Check for sane value in e_lfanew
        e_lfanew = struct.unpack("<L", dos_header[60:64])[0]
    if not e_lfanew or e_lfanew > PE_HEADER_LIMIT:
        offset = 0
        while offset < PE_HEADER_LIMIT - 86:
            # TODO
            try:
                machine_probe = struct.unpack("<H", buf[offset : offset + 2])[0]
            except struct.error:
                machine_probe = ""
            if machine_probe and machine_probe in {IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64}:
                nt_headers = buf[offset - 4 : offset + 252]
                break
            offset += 2
    else:
        nt_headers = buf[e_lfanew : e_lfanew + 256]

    if not nt_headers:
        return False

    try:
        # if ((pNtHeader->FileHeader.Machine == 0) || (pNtHeader->FileHeader.SizeOfOptionalHeader == 0 || pNtHeader->OptionalHeader.SizeOfHeaders == 0))
        if 0 in (
            struct.unpack("<H", nt_headers[4:6])[0],
            struct.unpack("<H", nt_headers[20:22])[0],
            struct.unpack("<H", nt_headers[84:86])[0],
        ):
            return False

        # if (!(pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
        if struct.unpack("<H", nt_headers[22:24])[0] & IMAGE_FILE_EXECUTABLE_IMAGE == 0:
            return False

        # if (pNtHeader->FileHeader.SizeOfOptionalHeader & (sizeof (ULONG_PTR) - 1))
        if struct.unpack("<H", nt_headers[20:22])[0] & 3 != 0:
            return False

        # if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
        if struct.unpack("<H", nt_headers[24:26])[0] not in {OPTIONAL_HEADER_MAGIC_PE, OPTIONAL_HEADER_MAGIC_PE_PLUS}:
            return False

    except struct.error:
        return False

    # After passing the above tests it should be safe to assume it's a PE image

    return True


class PortableExecutable:
    """PE analysis."""

    def __init__(self, file_path: str = False, data: bytes = False):
        """@param file_path: file path."""
        if file_path:
            self.file_path = file_path if isinstance(file_path, str) else file_path.decode()
        self._file_data = None
        self.pe = None
        self.HAVE_PE = False
        try:
            if data:
                self.pe = pefile.PE(data=data)
            else:
                self.pe = pefile.PE(self.file_path)
            self.HAVE_PE = True
        except Exception as e:
            log.error("PE type not recognised: %s", e)
        # self.results = results

    @property
    def file_data(self):
        if not self._file_data and path_exists(self.file_path):
            self._file_data = path_read_file(self.file_path)
        return self._file_data

    def is_64bit(self) -> bool:
        """Determines if a PE is 64bit.
        @return: True if 64bit, False if not
        """
        if not self.pe:
            return None
        if self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_AMD64:
            return True
        return False

    # Obtained from
    # https://github.com/erocarrera/pefile/blob/master/pefile.py
    # Copyright Ero Carrera and released under the MIT License:
    # https://github.com/erocarrera/pefile/blob/master/LICENSE

    def get_entropy(self, data: bytes) -> float:
        """Computes the entropy value for the provided data
        @param data: data to be analyzed.
        @return: entropy value as float.
        """
        entropy = 0.0

        if not data:
            return entropy

        occurrences = array.array("L", [0] * 256)

        for x in data:
            occurrences[x] += 1

        for x in occurrences:
            if x:
                p_x = float(x) / len(data)
                entropy -= p_x * math.log(p_x, 2)

        return entropy

    def get_peid_signatures(self, pe: pefile.PE) -> list:
        """Gets PEID signatures.
        @return: matched signatures or None.
        """
        if not pe or not HAVE_USERDB:
            return None

        try:
            result = userdb_signatures.match_all(pe, ep_only=True)
            if result:
                return list(result)
        except Exception as e:
            log.error(e, exc_info=True)

        return None

    def get_overlay_raw(self) -> int:
        """Get information on the PE overlay
        @return: overlay offset or None.
        """
        if not self.pe:
            return None

        return (
            self.pe.sections[self.pe.FILE_HEADER.NumberOfSections - 1].PointerToRawData
            + self.pe.sections[self.pe.FILE_HEADER.NumberOfSections - 1].SizeOfRawData
        )

    def get_overlay(self, pe: pefile.PE) -> dict:
        """Get information on the PE overlay
        @return: overlay dict or None.
        """
        if not pe:
            return None

        try:
            off = pe.get_overlay_data_start_offset()
        except Exception:
            log.error(
                "Your version of pefile is out of date.  "
                "Please update to the latest version on https://github.com/erocarrera/pefile"
            )
            return None

        if off is None:
            return None
        return {"offset": f"0x{off:08x}", "size": f"0x{len(pe.__data__) - off:08x}"}

    def get_reported_checksum(self, pe: pefile.PE) -> str:
        """Get checksum from optional header
        @return: checksum or None.
        """
        return f"0x{pe.OPTIONAL_HEADER.CheckSum:08x}" if pe else None

    def get_actual_checksum(self, pe: pefile.PE) -> str:
        """Get calculated checksum of PE
        @return: checksum or None.
        """
        if not pe:
            return None

        try:
            return f"0x{pe.generate_checksum():08x}"
        except Exception:
            return None

    def get_osversion(self, pe: pefile.PE) -> str:
        """Get minimum required OS version for PE to execute
        @return: minimum OS version or None.
        """
        return f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}" if pe else None

    # This function is duplicated
    def _get_filetype(self, data: bytes) -> str:
        """Gets filetype, uses libmagic if available.
        @param data: data to be analyzed.
        @return: file type or None.
        """
        if not HAVE_MAGIC:
            return None

        if not data:
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
            with suppress(Exception):
                ms.close()
        return file_type

    def get_resources(self, pe: pefile.PE) -> List[Dict[str, str]]:
        """Get resources.
        @return: resources dict or None.
        """
        if not pe:
            return None

        resources = []

        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return resources

        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            try:
                if resource_type.name is not None:
                    name = str(resource_type.name)
                else:
                    name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
                if hasattr(resource_type, "directory"):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, "directory"):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                resources.append(
                                    {
                                        "name": name,
                                        "offset": f"0x{resource_lang.data.struct.OffsetToData:08x}",
                                        "size": f"0x{resource_lang.data.struct.Size:08x}",
                                        "filetype": self._get_filetype(data),
                                        "language": pefile.LANG.get(resource_lang.data.lang),
                                        "sublanguage": pefile.get_sublang_name_for_lang(
                                            resource_lang.data.lang, resource_lang.data.sublang
                                        ),
                                        "entropy": f"{float(self.get_entropy(data)):.02f}",
                                    }
                                )
            except pefile.PEFormatError as e:
                log.debug("get_resources error: %s", str(e))
            except Exception as e:
                log.error(e, exc_info=True)
                continue

        return resources

    def get_pdb_path(self, pe: pefile.PE) -> str:
        if not pe or not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            return None

        try:
            for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                dbgst = dbg.struct
                dbgdata = pe.__data__[dbgst.PointerToRawData : dbgst.PointerToRawData + dbgst.SizeOfData]

                if dbgst.Type == 2:  # CODEVIEW
                    if dbgdata[:4] == b"RSDS":
                        return dbgdata[24:].decode("latin-1").rstrip("\0")
                    elif dbgdata[:4] == b"NB10":
                        return dbgdata[16:].decode("latin-1").rstrip("\0")
                elif dbgst.Type == 4:  # MISC
                    if len(dbgdata) == 9:
                        length = struct.unpack_from("IIB", dbgdata)[1]
                        return dbgdata[12:length].decode("latin-1").rstrip("\0")
        except Exception as e:
            log.error(e, exc_info=True)

        return None

    def get_imported_symbols(self, pe: pefile.PE) -> Dict[str, dict]:
        """Gets imported symbols.
        @return: imported symbols dict or None.
        """
        if not pe:
            return None

        imports = {}

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return imports

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                symbols = [
                    {"address": hex(imported_symbol.address), "name": imported_symbol.name.decode("latin-1")}
                    for imported_symbol in entry.imports
                    if imported_symbol.name and imported_symbol.address
                ]

                dll_name = entry.dll.decode("latin-1").split(".", 1)[0]
                if dll_name in imports:
                    imports[dll_name]["imports"].extend(symbols)
                else:
                    imports[dll_name] = {
                        "dll": entry.dll.decode("latin-1"),
                        "imports": symbols,
                    }
            except Exception as e:
                log.error(e, exc_info=True)
                continue
        return imports

    def get_exported_dll_name(self, pe: pefile.PE) -> str:
        """Gets exported DLL name, if any
        @return: exported DLL name as string or None.
        """
        if not pe:
            return None

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            dllname = pe.get_string_at_rva(pe.DIRECTORY_ENTRY_EXPORT.struct.Name)
            return dllname.decode("latin-1")
        return None

    def get_exported_symbols(self, pe: pefile.PE) -> List[dict]:
        """Gets exported symbols.
        @return: list of dicts of exported symbols or None.
        """
        if not pe:
            return None

        exports = []

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            exports.extend(
                {
                    "address": hex(pe.OPTIONAL_HEADER.ImageBase + exported_symbol.address),
                    "name": exported_symbol.name.decode("latin-1") if exported_symbol.name else "",
                    "ordinal": exported_symbol.ordinal,
                }
                for exported_symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols
            )

        return exports

    def get_directory_entries(self, pe: pefile.PE) -> List[Dict[str, str]]:
        """Gets image directory entries.
        @return: directory entries dict or None.
        """
        return (
            [
                {"name": entry.name, "virtual_address": f"0x{entry.VirtualAddress:08x}", "size": f"0x{entry.Size:08x}"}
                for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY
            ]
            if pe
            else None
        )

    def _convert_section_characteristics(self, val: int) -> str:
        flags = (
            "",
            "",
            "",
            "IMAGE_SCN_TYPE_NO_PAD",
            "",
            "IMAGE_SCN_CNT_CODE",
            "IMAGE_SCN_CNT_INITIALIZED_DATA",
            "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
            "IMAGE_SCN_LNK_OTHER",
            "IMAGE_SCN_LNK_INFO",
            "",
            "IMAGE_SCN_LNK_REMOVE",
            "IMAGE_SCN_LNK_COMDAT",
            "",
            "IMAGE_SCN_NO_DEFER_SPEC_EXC",
            "IMAGE_SCN_GPREL",
            "",
            "IMAGE_SCN_MEM_PURGEABLE",
            "IMAGE_SCN_MEM_LOCKED",
            "IMAGE_SCN_MEM_PRELOAD",
            # alignment bytes
            "",
            "",
            "",
            "",
            "IMAGE_SCN_LNK_NRELOC_OVFL",
            "IMAGE_SCN_MEM_DISCARDABLE",
            "IMAGE_SCN_MEM_NOT_CACHED",
            "IMAGE_SCN_MEM_NOT_PAGED",
            "IMAGE_SCN_MEM_SHARED",
            "IMAGE_SCN_MEM_EXECUTE",
            "IMAGE_SCN_MEM_READ",
            "IMAGE_SCN_MEM_WRITE",
        )
        alignment = (
            "",
            "IMAGE_SCN_ALIGN_1BYTES",
            "IMAGE_SCN_ALIGN_2BYTES",
            "IMAGE_SCN_ALIGN_4BYTES",
            "IMAGE_SCN_ALIGN_8BYTES",
            "IMAGE_SCN_ALIGN_16BYTES",
            "IMAGE_SCN_ALIGN_32BYTES",
            "IMAGE_SCN_ALIGN_64BYTES",
            "IMAGE_SCN_ALIGN_128BYTES",
            "IMAGE_SCN_ALIGN_256BYTES",
            "IMAGE_SCN_ALIGN_512BYTES",
            "IMAGE_SCN_ALIGN_1024BYTES",
            "IMAGE_SCN_ALIGN_2048BYTES",
            "IMAGE_SCN_ALIGN_4096BYTES",
            "IMAGE_SCN_ALIGN_8192BYTES",
            "",
        )
        tags = [flagstr for idx, flagstr in enumerate(flags) if flags[idx] and (val & (1 << idx))]

        if val & 0x00F00000:
            alignval = (val >> 20) & 0xF
            if alignment[alignval]:
                tags.append(alignment[alignval])

        return "|".join(tags)

    def get_sections(self, pe: pefile.PE) -> List[Dict[str, str]]:
        """Gets sections.
        @return: sections dict or None.
        """
        if not pe:
            return None

        sections = []

        for entry in pe.sections:
            try:
                sections.append(
                    {
                        "name": entry.Name.strip(b"\x00").decode("latin-1"),
                        "raw_address": f"0x{entry.PointerToRawData:08x}",
                        "virtual_address": f"0x{entry.VirtualAddress:08x}",
                        "virtual_size": f"0x{entry.Misc_VirtualSize:08x}",
                        "size_of_data": f"0x{entry.SizeOfRawData:08x}",
                        "characteristics": self._convert_section_characteristics(entry.Characteristics),
                        "characteristics_raw": f"0x{entry.Characteristics:08x}",
                        "entropy": f"{float(entry.get_entropy()):.02f}",
                    }
                )
            except Exception as e:
                log.error(e, exc_info=True)
                continue

        return sections

    def generate_icon_dhash(self, image: Image.Image, hash_size: int = 8) -> str:
        # based on https://gist.github.com/fr0gger/1263395ebdaf53e67f42c201635f256c
        image = image.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)

        difference = []

        for row, col in itertools.product(range(hash_size), range(hash_size)):
            pixel_left = image.getpixel((col, row))
            pixel_right = image.getpixel((col + 1, row))
            difference.append(pixel_left > pixel_right)

        decimal_value = 0
        hex_string = []

        for index, value in enumerate(difference):
            if value:
                decimal_value += 2 ** (index % 8)
            if index % 8 == 7:
                hex_string.append(f"{hex(decimal_value):2}"[2:].rjust(2, "0"))
                decimal_value = 0

        return "".join(hex_string)

    def get_icon_info(self, pe: pefile.PE) -> Tuple[str, str, str, str]:
        """Get icon in PNG format and information for searching for similar icons
        @return: tuple of (image data in PNG format encoded as base64, md5 hash of image data, md5 hash of "simplified"
         image for fuzzy matching)
        """
        if not pe or not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return None, None, None, None

        try:
            idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries]
            if pefile.RESOURCE_TYPE["RT_GROUP_ICON"] not in idx:
                return None, None, None, None
            try:
                rt_group_icon_idx = idx.index(pefile.RESOURCE_TYPE["RT_GROUP_ICON"])
                rt_group_icon_dir = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_group_icon_idx]
                entry = rt_group_icon_dir.directory.entries[0]
                offset = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                peicon = PEGroupIconDir(pe.get_memory_mapped_image()[offset : offset + size])
            except Exception as e:
                log.error(e)
                return None, None, None, None
            bigwidth = 0
            bigheight = 0
            bigbpp = 0
            bigidx = -1
            iconidx = 0
            if hasattr(peicon, "icons") and peicon.icons:
                for idx, icon in enumerate(peicon.icons):
                    if icon.bWidth >= bigwidth and icon.bHeight >= bigheight and icon.wBitCount >= bigbpp:
                        bigwidth = icon.bWidth
                        bigheight = icon.bHeight
                        bigbpp = icon.wBitCount
                        bigidx = icon.nID
                        iconidx = idx

            rt_icon_idx = False
            rt_icon_idx_tmp = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries]
            if pefile.RESOURCE_TYPE["RT_ICON"] in rt_icon_idx_tmp:
                rt_icon_idx = rt_icon_idx_tmp.index(pefile.RESOURCE_TYPE["RT_ICON"])
            if not isinstance(rt_icon_idx, int):
                return None, None, None, None
            rt_icon_dir = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_icon_idx]
            for entry in rt_icon_dir.directory.entries:
                if entry.id == bigidx:
                    offset = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size
                    icon = peicon.get_icon_file(iconidx, pe.get_memory_mapped_image()[offset : offset + size])

                    with BytesIO() as byteio:
                        byteio.write(icon)
                        byteio.seek(0)
                        try:
                            with Image.open(byteio) as img, BytesIO() as output:
                                img.save(output, format="PNG")

                                dhash = self.generate_icon_dhash(img)

                                img = (
                                    img.resize((8, 8), Image.BILINEAR)
                                    .convert("RGB")
                                    .convert("P", palette=Image.ADAPTIVE, colors=2)
                                    .convert("L")
                                )
                                lowval = img.getextrema()[0]
                                img = img.point(lambda i: 255 if i > lowval else 0).convert("1")
                                simplified = bytearray(img.getdata())

                                m = hashlib.md5()
                                m.update(output.getvalue())
                                fullhash = m.hexdigest()

                                m = hashlib.md5()
                                m.update(simplified)
                                simphash = m.hexdigest()
                                icon = base64.b64encode(output.getvalue()).decode()
                        except ValueError:
                            log.error("parse_pe.py -> get_incon_info -> buffer is not large enough")
                            return None, None, None, None
                        except OSError as e:
                            log.error(e)
                            return None, None, None, None
                    return icon, fullhash, simphash, dhash
        except Exception as e:
            log.error(e, exc_info=True)

        return None, None, None, None

    def get_versioninfo(self, pe: pefile.PE) -> List[dict]:
        """Get version info.
        @return: info dict or None.
        """
        if not pe:
            return None

        peresults = []

        if not hasattr(pe, "VS_VERSIONINFO") and not hasattr(pe, "FileInfo"):
            return peresults

        for infoentry in pe.FileInfo:
            for entry in infoentry:
                try:
                    if hasattr(entry, "StringTable"):
                        for st_entry in entry.StringTable:
                            for str_entry in st_entry.entries.items():
                                entry = {"name": str_entry[0].decode("latin-1"), "value": str_entry[1].decode("latin-1")}
                                if entry["name"] == "Translation" and len(entry["value"]) == 10:
                                    entry["value"] = f"0x0{entry['value'][2:5]} 0x0{entry['value'][7:10]}"
                                peresults.append(entry)
                    elif hasattr(entry, "Var"):
                        for var_entry in entry.Var:
                            if hasattr(var_entry, "entry"):
                                name = list(var_entry.entry.keys())[0]
                                value = list(var_entry.entry.values())[0]
                                if isinstance(name, bytes):
                                    name = name.decode("latin-1")
                                if isinstance(value, bytes):
                                    value = value.decode("latin-1")
                                entry = {
                                    "name": name,
                                    "value": value,
                                }
                                if entry["name"] == "Translation" and len(entry["value"]) == 10:
                                    entry["value"] = f"0x0{entry['value'][2:5]} 0x0{entry['value'][7:10]}"
                                peresults.append(entry)
                except Exception as e:
                    log.error(e, exc_info=True)
                    continue

        return peresults

    def get_imphash(self, pe: pefile.PE) -> str:
        """Gets imphash.
        @return: imphash string or None.
        """
        if not pe:
            return None

        try:
            return pe.get_imphash()
        except AttributeError:
            return None

    def get_timestamp(self, pe: pefile.PE) -> str:
        """Get compilation timestamp.
        @return: timestamp or None.
        """
        if not pe:
            return None

        try:
            pe_timestamp = pe.FILE_HEADER.TimeDateStamp
        except AttributeError:
            return None

        return datetime.fromtimestamp(pe_timestamp).strftime("%Y-%m-%d %H:%M:%S")

    def get_digital_signers(self, pe: pefile.PE) -> List[dict]:
        """If this executable is signed, get its signature(s)."""
        if not pe:
            return []

        if not HAVE_CRYPTO:
            log.critical("You do not have the cryptography library installed preventing certificate extraction. poetry install")
            return []

        dir_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]

        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) < dir_index:
            return []

        dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[dir_index]
        if not dir_entry or not dir_entry.VirtualAddress or not dir_entry.Size:
            return []

        retlist = []
        address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[dir_index].VirtualAddress

        # check if file is digitally signed
        if address == 0:
            return retlist

        certs = []
        try:
            signatures = pe.write()[address + 8 :]

            if isinstance(signatures, bytearray):
                signatures = bytes(signatures)

            with suppress(Exception):
                certs = backend.load_der_pkcs7_certificates(signatures)

        except AttributeError:
            log.debug("Can't get PE signatures")

        for cert in certs:
            md5 = binascii.hexlify(cert.fingerprint(hashes.MD5())).decode()
            sha1 = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
            sha256 = binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode()
            cert_data = {
                "md5_fingerprint": md5,
                "sha1_fingerprint": sha1,
                "sha256_fingerprint": sha256,
                "serial_number": str(cert.serial_number),
                "not_before": cert.not_valid_before.isoformat(),
                "not_after": cert.not_valid_after.isoformat(),
            }
            try:
                for attribute in cert.subject:
                    cert_data[f"subject_{attribute.oid._name}"] = attribute.value
            except ValueError as e:
                log.warning(e)
            try:
                for attribute in cert.issuer:
                    cert_data[f"issuer_{attribute.oid._name}"] = attribute.value
            except ValueError as e:
                log.warning(e)
            try:
                for extension in cert.extensions:
                    if extension.oid._name == "authorityKeyIdentifier" and extension.value.key_identifier:
                        cert_data[f"extensions_{extension.oid._name}"] = base64.b64encode(extension.value.key_identifier).decode()
                    elif extension.oid._name == "subjectKeyIdentifier" and extension.value.digest:
                        cert_data[f"extensions_{extension.oid._name}"] = base64.b64encode(extension.value.digest).decode()
                    elif extension.oid._name == "certificatePolicies":
                        for index, policy in enumerate(extension.value):
                            if policy.policy_qualifiers:
                                for qualifier in policy.policy_qualifiers:
                                    if qualifier.__class__ is not cryptography.x509.extensions.UserNotice:
                                        cert_data[f"extensions_{extension.oid._name}_{index}"] = qualifier
                    elif extension.oid._name == "cRLDistributionPoints":
                        for index, point in enumerate(extension.value):
                            for full_name in point.full_name:
                                cert_data[f"extensions_{extension.oid._name}_{index}"] = full_name.value
                    elif extension.oid._name == "authorityInfoAccess":
                        for authority_info in extension.value:
                            if authority_info.access_method._name == "caIssuers":
                                cert_data[f"extensions_{extension.oid._name}_caIssuers"] = authority_info.access_location.value
                            elif authority_info.access_method._name == "OCSP":
                                cert_data[f"extensions_{extension.oid._name}_OCSP"] = authority_info.access_location.value
                    elif extension.oid._name == "subjectAltName":
                        for index, name in enumerate(extension.value._general_names):
                            if isinstance(name.value, bytes):
                                cert_data[f"extensions_{extension.oid._name}_{index}"] = base64.b64encode(name.value).decode()
                            else:
                                cert_data[f"extensions_{extension.oid._name}_{index}"] = (
                                    name.value.rfc4514_string() if hasattr(name.value, "rfc4514_string") else name.value
                                )
            except ValueError:
                continue

            retlist.append(cert_data)

        return retlist

    def get_guest_digital_signers(self, task_id: str = False) -> dict:
        if not task_id:
            return {}
        cert_info_path = Path(CUCKOO_ROOT, "storage", "analyses", task_id, "aux", "DigiSig.json")
        if cert_info_path.exists():
            cert_data = json.loads(cert_info_path.read_text())
            if cert_data:
                return {
                    "aux_sha1": cert_data["sha1"],
                    "aux_timestamp": cert_data["timestamp"],
                    "aux_valid": cert_data["valid"],
                    "aux_error": cert_data["error"],
                    "aux_error_desc": cert_data["error_desc"],
                    "aux_signers": cert_data["signers"],
                }
        return {}

    def get_dll_exports(self) -> str:
        file_type = self._get_filetype(self.file_data)
        if HAVE_PEFILE and file_type and ("PE32" in file_type or "MS-DOS executable" in file_type) and self.HAVE_PE:
            try:
                if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
                    exports = []
                    for exported_symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        try:
                            if not exported_symbol.name:
                                continue
                            if isinstance(exported_symbol.name, bytes):
                                exports.append(re.sub(b"[^A-Za-z0-9_?@-]", b"", exported_symbol.name).decode())
                            else:
                                exports.append(re.sub("[^A-Za-z0-9_?@-]", "", exported_symbol.name))
                        except Exception as e:
                            log.error(e, exc_info=True)

                    return ",".join(exports)
            except Exception as e:
                log.error("PE type not recognised")
                log.error(e, exc_info=True)

        return ""

    def choose_dll_export(self) -> str:
        if not self.pe:
            return None
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    if not exp.name:
                        continue
                    if exp.name.decode() in ("DllInstall", "DllRegisterServer", "xlAutoOpen"):
                        return exp.name.decode()
                except Exception as e:
                    log.error(e, exc_info=True)
        return None

    def get_entrypoint(self, pe: pefile.PE) -> str:
        """Get entry point (PE).
        @return: entry point.
        """

        try:
            return f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08x}"
        except Exception:
            return None

    def get_imagebase(self, pe: pefile.PE) -> str:
        """Get information on the Image Base
        @return: image base or None.
        """
        try:
            return f"0x{pe.OPTIONAL_HEADER.ImageBase:08x}"
        except Exception:
            return None

    def get_ep_bytes(self, pe: pefile.PE) -> str:
        """Get entry point bytes (PE).
        @return: entry point bytes (16).
        """
        try:
            return binascii.b2a_hex(pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 0x10)).decode()
        except Exception:
            return None

    def run(self, task_id: str = False) -> dict:
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not path_exists(self.file_path):
            log.debug("File doesn't exist anymore")
            return {}

        # Advanced check if is real PE
        contents = path_read_file(self.file_path)
        if not IsPEImage(contents):
            return {}

        if not self.HAVE_PE:
            return {}

        peresults = {
            "guest_signers": self.get_guest_digital_signers(task_id),
            "digital_signers": self.get_digital_signers(self.pe),
            "imagebase": self.get_imagebase(self.pe),
            "entrypoint": self.get_entrypoint(self.pe),
            "ep_bytes": self.get_ep_bytes(self.pe),
            "peid_signatures": self.get_peid_signatures(self.pe),
            "reported_checksum": self.get_reported_checksum(self.pe),
            "actual_checksum": self.get_actual_checksum(self.pe),
            "osversion": self.get_osversion(self.pe),
            "pdbpath": self.get_pdb_path(self.pe),
            "imports": self.get_imported_symbols(self.pe),
            "exported_dll_name": self.get_exported_dll_name(self.pe),
            "exports": self.get_exported_symbols(self.pe),
            "dirents": self.get_directory_entries(self.pe),
            "sections": self.get_sections(self.pe),
            "overlay": self.get_overlay(self.pe),
            "resources": self.get_resources(self.pe),
            "versioninfo": self.get_versioninfo(self.pe),
            "imphash": self.get_imphash(self.pe),
            "timestamp": self.get_timestamp(self.pe),
        }
        (
            peresults["icon"],
            peresults["icon_hash"],
            peresults["icon_fuzzy"],
            peresults["icon_dhash"],
        ) = self.get_icon_info(self.pe)

        if peresults.get("imports", False):
            peresults["imported_dll_count"] = len(peresults["imports"])

        self.pe.close()
        return peresults
