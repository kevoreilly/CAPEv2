from __future__ import absolute_import
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


import os

try:
    import re2 as re
    HAVE_RE2 = True
except ImportError:
    HAVE_RE2 = False
    import re

import logging
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File, ProcDump
from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger(__name__)

class ProcessMemory(Processing):
    """Analyze process memory dumps."""
    order = 10

    def get_procmemory_pe(self, mem_pe):
        res = list()
        file_item = open(mem_pe.get("file"), "rb")

        for memmap in mem_pe.get("address_space") or []:
            if not memmap.get("PE"):
                continue
            data = b""
            for chunk in memmap["chunks"]:
                if int(chunk["start"], 16) >= int(memmap["start"], 16) and int(chunk["end"], 16) <= int(memmap["end"], 16):
                    file_item.seek(chunk["offset"])
                    data += file_item.read(int(chunk["size"], 16))

            #save pe to disk
            path = os.path.join(self.pmemory_path, "{}_{}".format(mem_pe["pid"], memmap["start"]))
            with open(path, "wb") as f:
                f.write(data)

            res.append(File(path).get_all())
        return res

    def run(self):
        """Run analysis.
        @return: structured results.
        """
        self.key = "procmemory"
        results = []
        do_strings = self.options.get("strings", False)
        nulltermonly = self.options.get("nullterminated_only", True)
        minchars = str(self.options.get("minchars", 5)).encode("utf-8")

        if os.path.exists(self.pmemory_path):
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
                for process in self.results.get("behavior", {}).get("processes", []) or []:
                    if process_id == process["process_id"]:
                        process_name = process["process_name"]
                        process_path = process["module_path"]

                procdump = ProcDump(dmp_path, pretty=True)

                proc = dict(
                    file=dmp_path,
                    pid=process_id,
                    name=process_name,
                    path=process_path,
                    yara=dmp_file.get_yara(os.path.join(CUCKOO_ROOT, "data", "yara", "index_memory.yar")),
                    address_space=procdump.pretty_print(),
                )

                #if self.options.get("extract_pe", False)
                extracted_pes = self.get_procmemory_pe(proc)

                endlimit = b""
                if not HAVE_RE2:
                    endlimit = b"8192"

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
                        strings.append(ws.decode("utf-16le").encode("utf-8"))

                    proc["strings_path"] = dmp_path + ".strings"
                    proc["extracted_pe"] = extracted_pes
                    f=open(proc["strings_path"], "wb")
                    f.write(b"\n".join(strings))
                    f.close()

                procdump.close()
                results.append(proc)
        return results

