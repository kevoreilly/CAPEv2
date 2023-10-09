# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import subprocess
from typing import Any, Dict, List

from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.utils import convert_to_printable

log = logging.getLogger(__name__)

# Note universal_newlines should be False as some binaries fails to convert bytes to text


class DotNETExecutable:
    """.NET analysis"""

    def __init__(self, file_path):
        self.file_path = file_path

    def _get_custom_attrs(self) -> List[Dict[str, str]]:
        try:
            ret = []
            output = subprocess.check_output(["/usr/bin/monodis", "--customattr", self.file_path], universal_newlines=False).split(
                b"\n"
            )
            for line in output[1:]:
                splitline = line.decode("latin-1").split()
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
                ret.append(
                    {
                        "type": convert_to_printable(typeval),
                        "name": convert_to_printable(nameval),
                        "value": convert_to_printable(valueval),
                    }
                )
            return ret
        except UnicodeDecodeError:
            log.error("UnicodeDecodeError: /usr/bin/monodis --customattr %s", self.file_path)
        except subprocess.CalledProcessError as e:
            log.error("Monodis: %s", str(e))
        except Exception as e:
            log.error(e, exc_info=True)
            return None

    def _get_assembly_refs(self) -> List[Dict[str, str]]:
        try:
            ret = []
            output = subprocess.check_output(["/usr/bin/monodis", "--assemblyref", self.file_path], universal_newlines=False).split(
                b"\n"
            )
            for idx, line in enumerate(output):
                splitline = line.decode("latin-1").split("Version=")
                if len(splitline) < 2:
                    continue
                verval = splitline[1]
                splitline = output[idx + 1].split(b"Name=")
                if len(splitline) < 2:
                    continue
                nameval = splitline[1]
                item = {
                    "name": convert_to_printable(nameval.decode()),
                    "version": convert_to_printable(verval),
                }
                ret.append(item)
            return ret

        except subprocess.CalledProcessError as e:
            log.error("Monodis: %s", str(e))
        except Exception as e:
            log.error(e, exc_info=True)
            return None

    def _get_assembly_info(self) -> Dict[str, str]:
        try:
            ret = {}
            output = subprocess.check_output(["/usr/bin/monodis", "--assembly", self.file_path], universal_newlines=False).split(
                b"\n"
            )
            for line in output:
                line = line.decode("latin-1")
                if line.startswith("Name:"):
                    ret["name"] = convert_to_printable(line[5:].strip())
                elif line.startswith("Version:"):
                    ret["version"] = convert_to_printable(line[8:].strip())
            return ret
        except subprocess.CalledProcessError as e:
            log.error("Monodis: %s", str(e))
        except Exception as e:
            log.error(e, exc_info=True)
            return None

    def _get_type_refs(self) -> List[Dict[str, str]]:
        try:
            ret = []
            output = subprocess.check_output(["/usr/bin/monodis", "--typeref", self.file_path], universal_newlines=False).split(
                b"\n"
            )
            for line in output[1:]:
                restline = "".join(line.decode("latin-1").split(":")[1:])
                restsplit = restline.split("]")
                asmname = restsplit[0][2:]
                typename = "".join(restsplit[1:])
                if asmname and typename:
                    item = {
                        "assembly": convert_to_printable(asmname),
                        "typename": convert_to_printable(typename),
                    }
                    ret.append(item)
            return ret

        except subprocess.CalledProcessError as e:
            log.error("Monodis: %s", str(e))
        except Exception as e:
            log.error(e, exc_info=True)
            return None

    def run(self) -> Dict[str, Any]:
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not path_exists(self.file_path):
            return None

        try:
            results = {
                "typerefs": self._get_type_refs(),
                "assemblyrefs": self._get_assembly_refs(),
                "assemblyinfo": self._get_assembly_info(),
                "customattrs": self._get_custom_attrs(),
            }

            if all(results):
                return results
            else:
                return
        except Exception as e:
            log.error(e, exc_info=True)
            return None
