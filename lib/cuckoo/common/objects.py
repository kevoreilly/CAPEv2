# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import binascii
import copy
import hashlib
import logging
import mmap
import os
import struct
import subprocess
import time

from lib.cuckoo.common.defines import (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
                                       PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY)

try:
    import magic

    HAVE_MAGIC = True
except ImportError:
    HAVE_MAGIC = False

try:
    import pydeep

    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False

try:
    import yara

    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

try:
    import pyclamd

    HAVE_CLAMAV = True
except ImportError:
    HAVE_CLAMAV = False

try:
    import re2 as re
except ImportError:
    import re

try:
    import pefile

    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

try:
    import tlsh

    HAVE_TLSH = True
except ImportError:
    print("Missed dependency: pip3 install python-tlsh")
    HAVE_TLSH = False

log = logging.getLogger(__name__)

FILE_CHUNK_SIZE = 16 * 1024

yara_error = {
    "1": "ERROR_INSUFFICIENT_MEMORY",
    "2": "ERROR_COULD_NOT_ATTACH_TO_PROCESS",
    "3": "ERROR_COULD_NOT_OPEN_FILE",
    "4": "ERROR_COULD_NOT_MAP_FILE",
    "6": "ERROR_INVALID_FILE",
    "7": "ERROR_CORRUPT_FILE",
    "8": "ERROR_UNSUPPORTED_FILE_VERSION",
    "9": "ERROR_INVALID_REGULAR_EXPRESSION",
    "10": "ERROR_INVALID_HEX_STRING",
    "11": "ERROR_SYNTAX_ERROR",
    "12": "ERROR_LOOP_NESTING_LIMIT_EXCEEDED",
    "13": "ERROR_DUPLICATED_LOOP_IDENTIFIER",
    "14": "ERROR_DUPLICATED_IDENTIFIER",
    "15": "ERROR_DUPLICATED_TAG_IDENTIFIER",
    "16": "ERROR_DUPLICATED_META_IDENTIFIER",
    "17": "ERROR_DUPLICATED_STRING_IDENTIFIER",
    "18": "ERROR_UNREFERENCED_STRING",
    "19": "ERROR_UNDEFINED_STRING",
    "20": "ERROR_UNDEFINED_IDENTIFIER",
    "21": "ERROR_MISPLACED_ANONYMOUS_STRING",
    "22": "ERROR_INCLUDES_CIRCULAR_REFERENCE",
    "23": "ERROR_INCLUDE_DEPTH_EXCEEDED",
    "24": "ERROR_WRONG_TYPE",
    "25": "ERROR_EXEC_STACK_OVERFLOW",
    "26": "ERROR_SCAN_TIMEOUT",
    "27": "ERROR_TOO_MANY_SCAN_THREADS",
    "28": "ERROR_CALLBACK_ERROR",
    "29": "ERROR_INVALID_ARGUMENT",
    "30": "ERROR_TOO_MANY_MATCHES",
    "31": "ERROR_INTERNAL_FATAL_ERROR",
    "32": "ERROR_NESTED_FOR_OF_LOOP",
    "33": "ERROR_INVALID_FIELD_NAME",
    "34": "ERROR_UNKNOWN_MODULE",
    "35": "ERROR_NOT_A_STRUCTURE",
    "36": "ERROR_NOT_INDEXABLE",
    "37": "ERROR_NOT_A_FUNCTION",
    "38": "ERROR_INVALID_FORMAT",
    "39": "ERROR_TOO_MANY_ARGUMENTS",
    "40": "ERROR_WRONG_ARGUMENTS",
    "41": "ERROR_WRONG_RETURN_TYPE",
    "42": "ERROR_DUPLICATED_STRUCTURE_MEMBER",
    "43": "ERROR_EMPTY_STRING",
    "44": "ERROR_DIVISION_BY_ZERO",
    "45": "ERROR_REGULAR_EXPRESSION_TOO_LARGE",
    "46": "ERROR_TOO_MANY_RE_FIBERS",
    "47": "ERROR_COULD_NOT_READ_PROCESS_MEMORY",
    "48": "ERROR_INVALID_EXTERNAL_VARIABLE_TYPE",
    "49": "ERROR_REGULAR_EXPRESSION_TOO_COMPLEX",
}

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
OPTIONAL_HEADER_MAGIC_PE = 0x10B
OPTIONAL_HEADER_MAGIC_PE_PLUS = 0x20B
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
DOS_HEADER_LIMIT = 0x40
PE_HEADER_LIMIT = 0x200


def IsPEImage(buf, size=False):
    if not buf:
        return False
    if not size:
        size = len(buf)
    if size < DOS_HEADER_LIMIT:
        return False
    if isinstance(buf, str):
        buf = buf.encode()
    dos_header = buf[:DOS_HEADER_LIMIT]
    nt_headers = None

    if size < PE_HEADER_LIMIT:
        return False

    # Check for sane value in e_lfanew
    (e_lfanew,) = struct.unpack("<L", dos_header[60:64])
    if not e_lfanew or e_lfanew > PE_HEADER_LIMIT:
        offset = 0
        while offset < PE_HEADER_LIMIT - 86:
            # ToDo
            try:
                machine_probe = struct.unpack("<H", buf[offset : offset + 2])[0]
            except struct.error:
                machine_probe = ""
            if machine_probe and machine_probe in (IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64):
                nt_headers = buf[offset - 4 : offset + 252]
                break
            offset += 2
    else:
        nt_headers = buf[e_lfanew : e_lfanew + 256]

    if not nt_headers:
        return False

    try:
        # if ((pNtHeader->FileHeader.Machine == 0) || (pNtHeader->FileHeader.SizeOfOptionalHeader == 0 || pNtHeader->OptionalHeader.SizeOfHeaders == 0))
        if (
            struct.unpack("<H", nt_headers[4:6]) == 0
            or struct.unpack("<H", nt_headers[20:22]) == 0
            or struct.unpack("<H", nt_headers[84:86]) == 0
        ):
            return False

        # if (!(pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
        if (struct.unpack("<H", nt_headers[22:24])[0] & IMAGE_FILE_EXECUTABLE_IMAGE) == 0:
            return False

        # if (pNtHeader->FileHeader.SizeOfOptionalHeader & (sizeof (ULONG_PTR) - 1))
        if struct.unpack("<H", nt_headers[20:22])[0] & 3 != 0:
            return False

        # if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
        if (
            struct.unpack("<H", nt_headers[24:26])[0] != OPTIONAL_HEADER_MAGIC_PE
            and struct.unpack("<H", nt_headers[24:26])[0] != OPTIONAL_HEADER_MAGIC_PE_PLUS
        ):
            return False

    except struct.error:
        return False

    # To pass the above tests it should now be safe to assume it's a PE image

    return True


class Dictionary(dict):
    """Cuckoo custom dict."""

    def __getattr__(self, key):
        return self.get(key)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class PCAP:
    """PCAP base object."""

    def __init__(self, file_path):
        self.file_path = file_path


class URL:
    """URL base object."""

    def __init__(self, url):
        """@param url: URL"""
        self.url = url


class File(object):
    """Basic file object class with all useful utilities."""

    # The yara rules should not change during one Cuckoo run and as such we're
    # caching 'em. This dictionary is filled during init_yara().
    yara_rules = {}
    yara_initialized = False
    # static fields which indicate whether the user has been
    # notified about missing dependencies already
    notified_yara = False
    notified_pydeep = False

    def __init__(self, file_path, guest_paths=None, file_name=None):
        """@param file_path: file path."""
        self.file_name = file_name
        self.file_path = file_path
        self.guest_paths = guest_paths

        # these will be populated when first accessed
        self._file_data = None
        self._crc32 = None
        self._md5 = None
        self._sha1 = None
        self._sha256 = None
        self._sha512 = None
        self._pefile = False
        self.file_type = None
        self.pe = None

    def get_name(self):
        """Get file name.
        @return: file name.
        """
        if self.file_name:
            return self.file_name
        file_name = os.path.basename(self.file_path)
        return file_name

    def valid(self):
        return os.path.exists(self.file_path) and os.path.isfile(self.file_path) and os.path.getsize(self.file_path) != 0

    def get_data(self):
        """Read file contents.
        @return: data.
        """
        return self.file_data

    def get_chunks(self):
        """Read file contents in chunks (generator)."""

        with open(self.file_path, "rb") as fd:
            while True:
                chunk = fd.read(FILE_CHUNK_SIZE)
                if not chunk:
                    break
                yield chunk

    def calc_hashes(self):
        """Calculate all possible hashes for this file."""
        crc = 0
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        sha3_384 = hashlib.sha3_384()

        if HAVE_TLSH:
            tlsh_hash = tlsh.Tlsh()

        for chunk in self.get_chunks():
            crc = binascii.crc32(chunk, crc)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
            sha3_384.update(chunk)
            if HAVE_TLSH:
                tlsh_hash.update(chunk)

        self._crc32 = "".join("%02X" % ((crc >> i) & 0xFF) for i in [24, 16, 8, 0])
        self._md5 = md5.hexdigest()
        self._sha1 = sha1.hexdigest()
        self._sha256 = sha256.hexdigest()
        self._sha512 = sha512.hexdigest()
        self._sha3_384 = sha3_384.hexdigest()
        if HAVE_TLSH:
            try:
                tlsh_hash.final()
                self._tlsh_hash = tlsh_hash.hexdigest()
            except ValueError:
                pass
                # print("TLSH: less than 50 of input, ignoring")

    @property
    def file_data(self):
        if not self._file_data:
            self._file_data = open(self.file_path, "rb").read()
        return self._file_data

    def get_size(self):
        """Get file size.
        @return: file size.
        """
        if os.path.exists(self.file_path):
            return os.path.getsize(self.file_path)
        else:
            return 0

    def get_crc32(self):
        """Get CRC32.
        @return: CRC32.
        """
        if not self._crc32:
            self.calc_hashes()
        return self._crc32

    def get_md5(self):
        """Get MD5.
        @return: MD5.
        """
        if not self._md5:
            self.calc_hashes()
        return self._md5

    def get_sha1(self):
        """Get SHA1.
        @return: SHA1.
        """
        if not self._sha1:
            self.calc_hashes()
        return self._sha1

    def get_sha256(self):
        """Get SHA256.
        @return: SHA256.
        """
        if not self._sha256:
            self.calc_hashes()
        return self._sha256

    def get_sha512(self):
        """
        Get SHA512.
        @return: SHA512.
        """
        if not self._sha512:
            self.calc_hashes()
        return self._sha512

    def get_sha3_384(self):
        """
        Get SHA3_384.
        @return: SHA3_384.
        """
        if not self._sha3_384:
            self.calc_hashes()
        return self._sha3_384

    def get_ssdeep(self):
        """Get SSDEEP.
        @return: SSDEEP.
        """
        if not HAVE_PYDEEP:
            if not File.notified_pydeep:
                File.notified_pydeep = True
                log.warning("Unable to import pydeep (install with `pip3 install pydeep`)")
            return None

        try:
            return pydeep.hash_file(self.file_path).decode()
        except Exception:
            return None

    def get_entrypoint(self, pe):
        """Get entry point (PE).
        @return: entry point.
        """

        try:
            return pe.OPTIONAL_HEADER.AddressOfEntryPoint
        except Exception:
            return None

    def get_ep_bytes(self, pe):
        """Get entry point bytes (PE).
        @return: entry point bytes (16).
        """
        try:
            return binascii.b2a_hex(pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 0x10)).decode()
        except Exception:
            return None

    def get_content_type(self):
        """Get MIME content file type (example: image/jpeg).
        @return: file content type.
        """
        file_type = None
        if os.path.exists(self.file_path):
            if HAVE_MAGIC:
                if hasattr(magic, "from_file"):
                    try:
                        file_type = magic.from_file(self.file_path)
                    except Exception as e:
                        log.error(e, exc_info=True)
                if not file_type and hasattr(magic, "open"):
                    try:
                        ms = magic.open(magic.MAGIC_MIME | magic.MAGIC_SYMLINK)
                        ms.load()
                        file_type = ms.file(self.file_path)
                        ms.close()
                    except Exception as e:
                        log.error(e, exc_info=True)

            if file_type is None:
                try:
                    p = subprocess.Popen(
                        ["file", "-b", "-L", "--mime-type", self.file_path], universal_newlines=True, stdout=subprocess.PIPE
                    )
                    file_type = p.stdout.read().strip()
                except Exception as e:
                    log.error(e, exc_info=True)

        return file_type

    def get_type(self):
        """Get MIME file type.
        @return: file type.
        """
        if self.file_type:
            return self.file_type
        if self.file_path:
            try:
                if IsPEImage(self.file_data):
                    self._pefile = True
                    if not HAVE_PEFILE:
                        if not File.notified_pefile:
                            File.notified_pefile = True
                            log.warning("Unable to import pefile (install with `pip3 install pefile`)")
                    else:
                        try:
                            self.pe = pefile.PE(data=self.file_data, fast_load=True)
                        except pefile.PEFormatError:
                            self.file_type = "PE image for MS Windows"
                            log.error("Unable to instantiate pefile on image")
                        if self.pe:
                            is_dll = self.pe.is_dll()
                            is_x64 = self.pe.FILE_HEADER.Machine == IMAGE_FILE_MACHINE_AMD64
                            gui_type = "console" if self.pe.OPTIONAL_HEADER.Subsystem == 3 else "GUI"
                            # Emulate magic for now
                            if is_dll and is_x64:
                                self.file_type = "PE32+ executable (DLL) (GUI) x86-64, for MS Windows"
                            elif is_dll:
                                self.file_type = "PE32 executable (DLL) (GUI) Intel 80386, for MS Windows"
                            elif is_x64:
                                self.file_type = f"PE32+ executable ({gui_type}) x86-64, for MS Windows"
                            else:
                                self.file_type = f"PE32 executable ({gui_type}) Intel 80386, for MS Windows"
            except Exception as e:
                log.error(e, exc_info=True)

            if not self.file_type:
                self.file_type = self.get_content_type()

        return self.file_type

    def _yara_encode_string(self, yara_string):
        # Beware, spaghetti code ahead.
        try:
            new = yara_string.decode()
        except UnicodeDecodeError as e:
            # yara_string = binascii.hexlify(yara_string.lstrip("uU")).upper()
            yara_string = binascii.hexlify(yara_string).upper()
            yara_string = b" ".join(yara_string[i : i + 2] for i in range(0, len(yara_string), 2))
            new = "{ %s }" % yara_string.decode()

        return new

    def get_yara(self, category="binaries", externals=None):
        """Get Yara signatures matches.
        @return: matched Yara signatures.
        """
        results = []
        if not HAVE_YARA:
            if not File.notified_yara:
                File.notified_yara = True
                log.warning("Unable to import yara (please compile from sources)")
            return results

        if not os.path.getsize(self.file_path):
            return results

        try:
            results, rule = [], File.yara_rules[category]
            if isinstance(self.file_path, bytes):
                path = self.file_path.decode()
            else:
                path = self.file_path
            for match in rule.match(path, externals=externals):
                strings = set()
                for s in match.strings:
                    strings.add(self._yara_encode_string(s[2]))

                addresses = {}
                for s in match.strings:
                    addresses[s[1].strip("$")] = s[0]

                results.append(
                    {
                        "name": match.rule,
                        "meta": match.meta,
                        "strings": list(strings),
                        "addresses": addresses,
                    }
                )
        except Exception as e:
            errcode = str(e).split()[-1]
            if errcode in yara_error:
                log.exception("Unable to match Yara signatures for %s: %s", self.file_path, yara_error[errcode])
            else:
                log.exception("Unable to match Yara signatures for %s: unknown code %s", self.file_path, errcode)

        return results

    def get_clamav(self):
        """Get ClamAV signatures matches.
        Requires pyclamd module. Additionally if running with apparmor, an exception must be made.
        apt-get install clamav clamav-daemon clamav-freshclam clamav-unofficial-sigs -y
        pip3 install -U pyclamd
        systemctl enable clamav-daemon
        systemctl start clamav-daemon
        usermod -a -G cuckoo clamav
        echo "/opt/CAPEv2/storage/** r," | sudo tee -a /etc/apparmor.d/local/usr.sbin.clamd
        @return: matched ClamAV signatures.
        """
        matches = []

        if HAVE_CLAMAV and os.path.getsize(self.file_path) > 0:
            try:
                cd = pyclamd.ClamdUnixSocket()
                results = cd.allmatchscan(self.file_path)
                if results:
                    for entry in results[self.file_path]:
                        if entry[0] == "FOUND" and entry[1] not in matches:
                            matches.append(entry[1])
            except ConnectionError as e:
                log.warning("failed to connect to clamd socket")
            except Exception as e:
                log.warning("failed to scan file with clamav {0}".format(e))
            finally:
                return matches
        return matches

    def get_tlsh(self):
        """
        Get TLSH.
        @return: TLSH.
        """
        if hasattr(self, "_tlsh_hash"):
            if not self._tlsh_hash:
                self.calc_hashes()
            return self._tlsh_hash
        else:
            return False

    def get_dll_exports(self):
        file_type = self.get_type()
        if HAVE_PEFILE and ("PE32" in file_type or "MS-DOS executable" in file_type):
            try:
                pe = pefile.PE(self.file_path)
                if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                    exports = []
                    for exported_symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
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

    def get_rh_hash(self):
        if not self.pe:
            return None

        # source https://github.com/RichHeaderResearch/RichPE/blob/master/richpe.py#L34
        rich_header = self.pe.parse_rich_header()
        if rich_header is None:
            return None

        # Get list of @Comp.IDs and counts from Rich header
        # Elements in rich_fields at even indices are @Comp.IDs
        # Elements in rich_fields at odd indices are counts
        rich_fields = rich_header.get("values")
        if len(rich_fields) % 2 != 0:
            return None

        # The RichPE hash of a file is computed by computing the md5 of specific
        # metadata within  the Rich header and the PE header
        md5 = hashlib.md5()

        # Update hash using @Comp.IDs and masked counts from Rich header
        while len(rich_fields):
            compid = rich_fields.pop(0)
            count = rich_fields.pop(0)
            mask = 2 ** (count.bit_length() // 2 + 1) - 1
            count |= mask
            md5.update(struct.pack("<L", compid))
            md5.update(struct.pack("<L", count))

        # Update hash using metadata from the PE header
        md5.update(struct.pack("<L", self.pe.FILE_HEADER.Machine))
        md5.update(struct.pack("<L", self.pe.FILE_HEADER.Characteristics))
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.Subsystem))
        md5.update(struct.pack("<B", self.pe.OPTIONAL_HEADER.MajorLinkerVersion))
        md5.update(struct.pack("<B", self.pe.OPTIONAL_HEADER.MinorLinkerVersion))
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion))
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion))
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.MajorImageVersion))
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.MinorImageVersion))
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.MajorSubsystemVersion))
        md5.update(struct.pack("<L", self.pe.OPTIONAL_HEADER.MinorSubsystemVersion))

        # Close PE file and return RichPE hash digest
        return md5.hexdigest()

    def get_all(self):
        """Get all information available.
        @return: information dict.
        """

        infos = {}
        infos["name"] = self.get_name()
        infos["path"] = self.file_path
        infos["guest_paths"] = self.guest_paths
        infos["size"] = self.get_size()
        infos["crc32"] = self.get_crc32()
        infos["md5"] = self.get_md5()
        infos["sha1"] = self.get_sha1()
        infos["sha256"] = self.get_sha256()
        infos["sha512"] = self.get_sha512()
        infos["rh_hash"] = self.get_rh_hash()
        infos["ssdeep"] = self.get_ssdeep()
        infos["type"] = self.get_type()
        infos["yara"] = self.get_yara()
        infos["cape_yara"] = self.get_yara(category="CAPE")
        infos["clamav"] = self.get_clamav()
        infos["tlsh"] = self.get_tlsh()
        infos["sha3_384"] = self.get_sha3_384()

        if self.pe:
            infos["entrypoint"] = self.get_entrypoint(self.pe)
            infos["ep_bytes"] = self.get_ep_bytes(self.pe)
            infos["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(self.pe.FILE_HEADER.TimeDateStamp))

        return infos, self.pe


class Static(File):
    pass


class ProcDump(object):
    def __init__(self, dump_file, pretty=False):
        self._dumpfile = open(dump_file, "rb")
        self.dumpfile = mmap.mmap(self._dumpfile.fileno(), 0, access=mmap.ACCESS_READ)
        self.address_space = self.parse_dump()
        self.protmap = {
            PAGE_NOACCESS: "NOACCESS",
            PAGE_READONLY: "R",
            PAGE_READWRITE: "RW",
            PAGE_WRITECOPY: "RWC",
            PAGE_EXECUTE: "X",
            PAGE_EXECUTE_READ: "RX",
            PAGE_EXECUTE_READWRITE: "RWX",
            PAGE_EXECUTE_WRITECOPY: "RWXC",
        }

    def __del__(self):
        self.close()

    def close(self):
        if self.dumpfile:
            self.dumpfile.close()
            self.dumpfile = None
        if self._dumpfile:
            self._dumpfile.close()
            self._dumpfile = None

    def _prot_to_str(self, prot):
        if prot & PAGE_GUARD:
            return "G"
        prot &= 0xFF
        return self.protmap[prot]

    def pretty_print(self):
        new_addr_space = copy.deepcopy(self.address_space)
        for map in new_addr_space:
            map["start"] = "0x%.08x" % map["start"]
            map["end"] = "0x%.08x" % map["end"]
            map["size"] = "0x%.08x" % map["size"]
            if map["prot"] is None:
                map["prot"] = "Mixed"
            else:
                map["prot"] = self._prot_to_str(map["prot"])
            for chunk in map["chunks"]:
                chunk["start"] = "0x%.08x" % chunk["start"]
                chunk["end"] = "0x%.08x" % chunk["end"]
                chunk["size"] = "0x%.08x" % chunk["size"]
                chunk["prot"] = self._prot_to_str(chunk["prot"])
        return new_addr_space

    def _coalesce_chunks(self, chunklist):
        low = chunklist[0]["start"]
        high = chunklist[-1]["end"]
        prot = chunklist[0]["prot"]
        PE = chunklist[0]["PE"]
        for chunk in chunklist:
            if chunk["prot"] != prot:
                prot = None
        return {"start": low, "end": high, "size": high - low, "prot": prot, "PE": PE, "chunks": chunklist}

    def parse_dump(self):
        f = self.dumpfile
        address_space = []
        curchunk = []
        lastend = 0
        while True:
            data = f.read(24)
            if data == b"":
                break
            alloc = {}
            addr, size, mem_state, mem_type, mem_prot = struct.unpack("QIIII", data)
            offset = f.tell()
            if addr != lastend and len(curchunk):
                address_space.append(self._coalesce_chunks(curchunk))
                curchunk = []
            lastend = addr + size
            alloc["start"] = addr
            alloc["end"] = addr + size
            alloc["size"] = size
            alloc["prot"] = mem_prot
            alloc["state"] = mem_state
            alloc["type"] = mem_type
            alloc["offset"] = offset
            alloc["PE"] = False
            try:
                if f.read(2) == b"MZ":
                    alloc["PE"] = True
                f.seek(size - 2, 1)
            except Exception:
                break
            curchunk.append(alloc)
        if len(curchunk):
            address_space.append(self._coalesce_chunks(curchunk))

        f.seek(0)

        return address_space

    def get_data(self, addr, size):
        for map in self.address_space:
            if addr < map["start"] or addr >= map["end"]:
                continue
            for chunk in map["chunks"]:
                if addr < chunk["start"] or addr >= chunk["end"]:
                    continue
                maxsize = chunk["start"] + chunk["size"] - addr
                if size > maxsize:
                    size = maxsize
                self.dumpfile.seek(chunk["offset"] + addr - chunk["start"])
                return self.dumpfile.read(size)

    def search(self, regex, flags=0, all=False):
        if all:
            result = {}
            result["detail"] = []
            matches = []
            for map in self.address_space:
                for chunk in map["chunks"]:
                    self.dumpfile.seek(chunk["offset"])
                    match = re.finditer(regex, self.dumpfile.read(chunk["end"] - chunk["start"]), flags)
                    thismatch = []
                    try:
                        while True:
                            m = next(match)
                            thismatch.append(m)
                            matches.append(m.group(0))
                    except StopIteration:
                        pass
                    if thismatch:
                        result["detail"].append({"match": thismatch, "chunk": chunk})
            result["matches"] = matches
            return result
        else:
            for map in self.address_space:
                for chunk in map["chunks"]:
                    self.dumpfile.seek(chunk["offset"])
                    match = re.search(regex, self.dumpfile.read(chunk["end"] - chunk["start"]), flags)
                    if match:
                        result = {}
                        result["match"] = match
                        result["chunk"] = chunk
                        return result
