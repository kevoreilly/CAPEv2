# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
from subprocess import PIPE, Popen

from lib.cuckoo.common.utils import convert_to_printable

log = logging.getLogger(__name__)


class DotNETExecutable(object):
    """.NET analysis"""

    def __init__(self, file_path):
        self.file_path = file_path

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
            results["typerefs"] = self._get_type_refs()
            results["assemblyrefs"] = self._get_assembly_refs()
            results["assemblyinfo"] = self._get_assembly_info()
            results["customattrs"] = self._get_custom_attrs()

            if results != {"typerefs": [], "assemblyrefs": [], "assemblyinfo": {}, "customattrs": []}:
                return results
            else:
                return
        except Exception as e:
            log.error(e, exc_info=True)
            return None
