# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ctypes
import logging
import struct
from typing import Any, Dict, Tuple

from lib.cuckoo.common.structures import LnkEntry, LnkHeader

try:
    import LnkParse3
    from LnkParse3.exceptions import LnkParserError

    HAVE_LNK3 = True
except ImportError:
    HAVE_LNK3 = False

log = logging.getLogger(__name__)


class LnkShortcut:
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

    def __init__(self, filepath: str = None):
        self.filepath = filepath

    def read_uint16(self, offset: int) -> int:
        return struct.unpack("H", self.buf[offset : offset + 2])[0]

    def read_uint32(self, offset: int) -> int:
        return struct.unpack("I", self.buf[offset : offset + 4])[0]

    def read_stringz(self, offset: int) -> bytes:
        return self.buf[offset : self.buf.index(b"\x00", offset)]

    def read_string16(self, offset: int) -> Tuple[int, str]:
        length = self.read_uint16(offset) * 2
        ret = self.buf[offset + 2 : offset + 2 + length].decode("utf16")
        return offset + 2 + length, ret

    def run(self) -> Dict[str, Any]:
        with open(self.filepath, "rb") as f:
            if HAVE_LNK3:
                try:
                    data = LnkParse3.lnk_file(f).get_json(get_all=True)
                    if "creation_time" in data.get("header", {}) and data["header"].get("creation_time"):
                        data["header"]["creation_time"] = data["header"]["creation_time"].strftime("%Y-%m-%d %H:%S:%M")
                    if "accessed_time" in data.get("header", {}) and data["header"].get("accessed_time"):
                        data["header"]["accessed_time"] = data["header"]["accessed_time"].strftime("%Y-%m-%d %H:%S:%M")
                    if "modified_time" in data.get("header", {}) and data["header"].get("modified_time"):
                        data["header"]["modified_time"] = data["header"]["modified_time"].strftime("%Y-%m-%d %H:%S:%M")
                except (LnkParserError, struct.error) as e:
                    log.error("Parse LNK error: %s", str(e))
                    return {}
                # breaks json due to datetime objects
                if "target" in data:
                    del data["target"]
                return data
            else:
                self.buf = f.read()
                if len(self.buf) < ctypes.sizeof(LnkHeader):
                    log.warning("Provided .lnk file is corrupted or incomplete")
                    return

                header = LnkHeader.from_buffer_copy(self.buf[: ctypes.sizeof(LnkHeader)])
                if header.signature.copy() != self.signature or header.guid.copy() != self.guid:
                    return

                ret = {"flags": {}, "attrs": []}

                for x in range(7):
                    ret["flags"][self.flags[x]] = bool(header.flags & (1 << x))

                for x in range(14):
                    if header.attrs & (1 << x):
                        ret["attrs"].append(self.attrs[x])

                offset = 78 + self.read_uint16(76)
                if len(self.buf) < offset + 28:
                    log.warning("Provided .lnk file is corrupted or incomplete")
                    return

                off = LnkEntry.from_buffer_copy(self.buf[offset : offset + 28])

                # Local volume.
                if off.volume_flags & 1:
                    ret["basepath"] = self.read_stringz(offset + off.base_path)
                # Network volume.
                else:
                    try:
                        ret["net_share"] = self.read_stringz(offset + off.net_volume + 20)
                    except (TypeError, ValueError):
                        log.error("parse_lnk: subsection not found")

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
