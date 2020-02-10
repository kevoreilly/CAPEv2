# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import binascii
import hashlib
import logging
import os
import subprocess
import mmap
import struct
import copy

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.defines import PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE, PAGE_EXECUTE_READ
from lib.cuckoo.common.defines import PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE

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
    import pefile
    import peutils
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False

try:
    import re2 as re
except ImportError:
    import re

log = logging.getLogger(__name__)

FILE_CHUNK_SIZE = 16 * 1024

CAPE_YARA_RULEPATH = \
    os.path.join(CUCKOO_ROOT, "data", "yara", "index_CAPE.yar")

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


class Dictionary(dict):
    """Cuckoo custom dict."""

    def __getattr__(self, key):
        return self.get(key, None)

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

    YARA_RULEPATH = \
        os.path.join(CUCKOO_ROOT, "data", "yara", "index_binaries.yar")

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
        self._crc32     = None
        self._md5       = None
        self._sha1      = None
        self._sha256    = None
        self._sha512    = None
        self._pefile    = False

    def get_name(self):
        """Get file name.
        @return: file name.
        """
        if self.file_name:
            return self.file_name
        file_name = os.path.basename(self.file_path)
        return file_name

    def valid(self):
        return os.path.exists(self.file_path) and \
            os.path.isfile(self.file_path) and \
            os.path.getsize(self.file_path) != 0

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
                if not chunk: break
                yield chunk

    def calc_hashes(self):
        """Calculate all possible hashes for this file."""
        crc    = 0
        md5    = hashlib.md5()
        sha1   = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()

        for chunk in self.get_chunks():
            crc = binascii.crc32(chunk, crc)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

        self._crc32  = "".join("%02X" % ((crc>>i)&0xff) for i in [24, 16, 8, 0])
        self._md5    = md5.hexdigest()
        self._sha1   = sha1.hexdigest()
        self._sha256 = sha256.hexdigest()
        self._sha512 = sha512.hexdigest()

    @property
    def file_data(self):
        if not self._file_data: self._file_data = open(self.file_path, "rb").read()
        return self._file_data

    def get_size(self):
        """Get file size.
        @return: file size.
        """
        return os.path.getsize(self.file_path)

    def get_crc32(self):
        """Get CRC32.
        @return: CRC32.
        """
        if not self._crc32: self.calc_hashes()
        return self._crc32

    def get_md5(self):
        """Get MD5.
        @return: MD5.
        """
        if not self._md5: self.calc_hashes()
        return self._md5

    def get_sha1(self):
        """Get SHA1.
        @return: SHA1.
        """
        if not self._sha1: self.calc_hashes()
        return self._sha1

    def get_sha256(self):
        """Get SHA256.
        @return: SHA256.
        """
        if not self._sha256: self.calc_hashes()
        return self._sha256

    def get_sha512(self):
        """
        Get SHA512.
        @return: SHA512.
        """
        if not self._sha512: self.calc_hashes()
        return self._sha512

    def get_ssdeep(self):
        """Get SSDEEP.
        @return: SSDEEP.
        """
        if not HAVE_PYDEEP:
            if not File.notified_pydeep:
                File.notified_pydeep = True
                log.warning("Unable to import pydeep (install with `pip install pydeep`)")
            return None

        try:
            return pydeep.hash_file(self.file_path).decode("utf-8")
        except Exception:
            return None

    def get_entrypoint(self):
        """Get entry point (PE).
        @return: entry point.
        """
        if not HAVE_PEFILE:
            if not File.notified_pefile:
                File.notified_pefile = True
                log.warning("Unable to import pefile (install with `pip install pefile`)")
            return None

        try:
            pe = pefile.PE(data=self.file_data)
            return pe.OPTIONAL_HEADER.AddressOfEntryPoint
        except Exception:
            return None

    def get_ep_bytes(self):
        """Get entry point bytes (PE).
        @return: entry point bytes (16).
        """
        if not HAVE_PEFILE:
            if not File.notified_pefile:
                File.notified_pefile = True
                log.warning("Unable to import pefile (install with `pip install pefile`)")
            return None

        try:
            pe = pefile.PE(data=self.file_data)
            return binascii.b2a_hex(pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 0x10))
        except Exception:
            return None

    def get_type(self):
        """Get MIME file type.
        @return: file type.
        """
        file_type = None
        if HAVE_MAGIC:
            try:
                ms = magic.open(magic.MAGIC_SYMLINK)
                ms.load()
                file_type = ms.file(self.file_path)
            except:
                try:
                    file_type = magic.from_file(self.file_path)
                except:
                    pass
            finally:
                try:
                    ms.close()
                except:
                    pass

        if file_type is None:
            try:
                p = subprocess.Popen(["file", "-b", "-L", self.file_path],
                                     stdout=subprocess.PIPE)
                file_type = p.stdout.read().strip()
            except:
                pass

        return file_type

    def get_content_type(self):
        """Get MIME content file type (example: image/jpeg).
        @return: file content type.
        """
        file_type = None
        if HAVE_MAGIC:
            try:
                ms = magic.open(magic.MAGIC_MIME|magic.MAGIC_SYMLINK)
                ms.load()
                file_type = ms.file(self.file_path)
            except:
                try:
                    file_type = magic.from_file(self.file_path, mime=True)
                except:
                    pass
            finally:
                try:
                    ms.close()
                except:
                    pass

        if file_type is None:
            try:
                p = subprocess.Popen(["file", "-b", "-L", "--mime-type", self.file_path],
                                     stdout=subprocess.PIPE)
                file_type = p.stdout.read().strip()
            except:
                pass

        return file_type

    def _yara_encode_string(self, s):
        # Beware, spaghetti code ahead.
        try:
            new = s#.encode("utf-8")
        except UnicodeDecodeError:
            s = binascii.hexlify(s.lstrip("uU")).upper()
            s = " ".join(s[i:i+2] for i in range(0, len(s), 2))
            new = "{ %s }" % s

        return new

    def get_yara(self, rulepath=YARA_RULEPATH):
        """Get Yara signatures matches.
        @return: matched Yara signatures.
        """
        results = []

        if not HAVE_YARA:
            if not File.notified_yara:
                File.notified_yara = True
                log.warning("Unable to import yara (please compile from sources)")
            return results

        if not os.path.exists(rulepath):
            log.warning("The specified rule file at %s doesn't exist, skip",
                        rulepath)
            return results

        if not os.path.getsize(self.file_path):
            return results

        try:
            rules = False
            externals = {}
            try:
                filepath = ""
                filename = ""
                if self.file_name:
                    filepath = self.file_name
                    filename = self.file_name
                if self.guest_paths:
                    filepath = self.guest_paths[0]
                if filepath and filename:
                    externals = {"filepath": filepath, "filename": filename}
                rules = yara.compile(rulepath, externals=externals)
            except yara.SyntaxError as e:
                if 'duplicated identifier' in e.args[0]:
                    log.warning("Duplicate rule in %s, rulepath")
                    log.warning(e.args[0])
                else:
                    rules = yara.compile(rulepath)
            if rules:
                matches = rules.match(self.file_path)#.decode())

                results = []

                for match in matches:
                    strings = set()
                    for s in match.strings:
                        strings.add(self._yara_encode_string(s[2]))

                    addresses = {}
                    for s in match.strings:
                        addresses[s[1].strip('$')] = s[0]

                    results.append({
                        "name": match.rule,
                        "meta": match.meta,
                        "strings": list(strings),
                        "addresses": addresses,
                    })

        except Exception as e:
            errcode = e.message.split()[-1]
            if errcode in yara_error:
                log.exception("Unable to match Yara signatures for %s: %s",
                               self.file_path, yara_error[errcode])
            else:
                log.exception("Unable to match Yara signatures for %s: unknown code %s",
                              self.file_path, errcode)

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
            except:
                log.warning("failed to connect to clamd socket")
                return matches
            try:
                results = cd.allmatchscan(self.file_path)
            except Exception as e:
                log.warning("failed to scan file with clamav {0}".format(e))
                return matches
            if results:
                for key in results:
                    for entry in results[key]:
                        if entry[0] == "FOUND" and entry[1] not in matches:
                                matches.append(entry[1])

        return matches

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
        infos["ssdeep"] = self.get_ssdeep()
        infos["type"] = self.get_type()
        infos["yara"] = self.get_yara()
        infos["cape_yara"] = self.get_yara(CAPE_YARA_RULEPATH)
        infos["clamav"] = self.get_clamav()
        infos["entrypoint"] = self.get_entrypoint()
        infos["ep_bytes"] = self.get_ep_bytes()

        return infos

class Static(File):
    pass

class ProcDump(object):
    def __init__(self, dump_file, pretty=False):
        self._dumpfile = open(dump_file, "rb")
        self.dumpfile = mmap.mmap(self._dumpfile.fileno(), 0, access=mmap.ACCESS_READ)
        self.address_space = self.parse_dump()
        self.protmap = protmap = {
            PAGE_NOACCESS : "NOACCESS",
            PAGE_READONLY : "R",
            PAGE_READWRITE : "RW",
            PAGE_WRITECOPY : "RWC",
            PAGE_EXECUTE : "X",
            PAGE_EXECUTE_READ : "RX",
            PAGE_EXECUTE_READWRITE : "RWX",
            PAGE_EXECUTE_WRITECOPY : "RWXC",
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
        prot &= 0xff
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
        return { "start" : low, "end" : high, "size" : high - low, "prot" : prot, "PE" : PE, "chunks" : chunklist }

    def parse_dump(self):
        f = self.dumpfile
        address_space = []
        curchunk = []
        lastend = 0
        while True:
            data = f.read(24)
            if data == b'':
                break
            alloc = dict()
            addr,size,mem_state,mem_type,mem_prot = struct.unpack("QIIII", data)
            offset = f.tell()
            if addr != lastend and len(curchunk):
                address_space.append(self._coalesce_chunks(curchunk))
                curchunk = []
            lastend = addr + size
            alloc["start"] = addr
            alloc["end"] = (addr + size)
            alloc["size"] = size
            alloc["prot"] = mem_prot
            alloc["state"] = mem_state
            alloc["type"] = mem_type
            alloc["offset"] = offset
            alloc["PE"] = False
            try:
                if f.read(2) == b"MZ":
                    alloc["PE"] = True
                f.seek(size-2, 1)
            except:
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
            result = dict()
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
                        result = dict()
                        result["match"] = match
                        result["chunk"] = chunk
                        return result

