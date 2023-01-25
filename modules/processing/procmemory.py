# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.cape_utils import cape_name_from_yara
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File, ProcDump
from lib.cuckoo.common.path_utils import path_exists, path_write_file
from lib.cuckoo.common.utils import add_family_detection

processing_conf = Config("processing")

log = logging.getLogger(__name__)

try:
    import re2  # noqa: F401

    HAVE_RE2 = True
except ImportError:
    HAVE_RE2 = False


class ProcessMemory(Processing):
    """Analyze process memory dumps."""

    order = 10

    def get_procmemory_pe(self, mem_pe):
        res = []
        with open(mem_pe.get("path"), "rb") as file_item:
            for memmap in mem_pe.get("address_space") or []:
                if not memmap.get("PE"):
                    continue
                data = b""
                for chunk in memmap["chunks"]:
                    if int(chunk["start"], 16) >= int(memmap["start"], 16) and int(chunk["end"], 16) <= int(memmap["end"], 16):
                        file_item.seek(chunk["offset"])
                        data += file_item.read(int(chunk["size"], 16))

                # save pe to disk
                path = os.path.join(self.pmemory_path, f"{mem_pe['pid']}_{memmap['start']}")
                _ = path_write_file(path, data)

                data, pefile_object = File(path).get_all()
                if pefile_object:
                    self.results.setdefault("pefiles", {})
                    self.results["pefiles"].setdefault(data["sha256"], pefile_object)
                res.append(data)
        return res

    def get_yara_memblock(self, addr_space, yaraoffset):
        lastoffset = 0
        lastmemmap = addr_space[0]
        for memmap in addr_space:
            for chunk in memmap["chunks"]:
                offset = chunk["offset"]
                if offset > yaraoffset > lastoffset:
                    if int(memmap["start"], 16) < int(chunk["start"], 16) < int(memmap["end"], 16):
                        return memmap["start"]
                    else:
                        return lastmemmap["start"]
                lastoffset = offset
            lastmemmap = memmap

    def run(self):
        """Run analysis.
        @return: structured results.
        """
        self.key = "procmemory"
        results = []
        do_strings = self.options.get("strings", False)
        nulltermonly = self.options.get("nullterminated_only", True)
        minchars = str(self.options.get("minchars", 5)).encode()

        if path_exists(self.pmemory_path):
            for dmp in os.listdir(self.pmemory_path):
                # if we're re-processing this task, this means if zips are enabled, we won't do any reprocessing on the
                # process dumps (only matters for now for Yara)
                if not dmp.endswith(".dmp"):
                    continue

                dmp_path = os.path.join(self.pmemory_path, dmp)
                if os.path.getsize(dmp_path) == 0:
                    continue

                dmp_file = File(dmp_path)
                process_name = ""
                process_path = ""
                process_id = int(os.path.splitext(os.path.basename(dmp_path))[0])
                for process in self.results.get("behavior", {}).get("processes", []):
                    if process_id == process["process_id"]:
                        process_name = process["process_name"]
                        process_path = process["module_path"]

                procdump = ProcDump(dmp_path, pretty=True)

                proc = dict(
                    path=dmp_path,
                    sha256=dmp_file.get_sha256(),
                    pid=process_id,
                    name=process_name,
                    proc_path=process_path,
                    yara=dmp_file.get_yara(category="memory"),
                    cape_yara=dmp_file.get_yara(category="CAPE"),
                    address_space=procdump.pretty_print(),
                )

                for hit in proc["cape_yara"]:
                    hit["memblocks"] = {}
                    for item in hit["addresses"]:
                        memblock = self.get_yara_memblock(proc["address_space"], hit["addresses"][item])
                        if memblock:
                            hit["memblocks"][item] = memblock

                # if self.options.get("extract_pe", False)
                extracted_pes = self.get_procmemory_pe(proc)

                endlimit = b"" if HAVE_RE2 else b"8192"
                if do_strings:
                    if nulltermonly:
                        apat = b"([\x20-\x7e]{" + minchars + b"," + endlimit + b"})\x00"
                        upat = b"((?:[\x20-\x7e][\x00]){" + minchars + b"," + endlimit + b"})\x00\x00"
                    else:
                        apat = b"[\x20-\x7e]{" + minchars + b"," + endlimit + b"}"
                        upat = b"(?:[\x20-\x7e][\x00]){" + minchars + b"," + endlimit + b"}"

                    matchdict = procdump.search(apat, all=True)
                    strings = matchdict["matches"]
                    matchdict = procdump.search(upat, all=True)
                    ustrings = matchdict["matches"]
                    for ws in ustrings:
                        strings.append(ws.decode("utf-16le").encode())

                    proc["strings_path"] = f"{dmp_path}.strings"
                    proc["extracted_pe"] = extracted_pes
                    _ = path_write_file(proc["strings_path"], b"\n".join(strings))
                procdump.close()
                results.append(proc)

                if processing_conf.detections.yara:
                    cape_name = cape_name_from_yara(proc, process_id, self.results)
                    if cape_name:
                        add_family_detection(self.results, cape_name, "Yara", proc["sha256"])
        return results
