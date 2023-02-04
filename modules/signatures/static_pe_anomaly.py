# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
from datetime import datetime

from lib.cuckoo.common.abstracts import Signature


class PEAnomaly(Signature):
    name = "static_pe_anomaly"
    description = "Anomalous binary characteristics"
    severity = 3
    confidence = 80
    weight = 0
    categories = ["static"]
    authors = ["Optiv"]
    minimum = "1.2"

    def run(self):
        # set the bad date to a year prior to the release date of the OS
        bad_date_map = {
            # version , year, month
            "4.0": (1995, 6),
            "5.0": (1999, 2),
            "5.1": (2000, 10),
            "5.2": (2002, 3),
            "6.0": (2005, 11),
            "6.1": (2008, 10),
            "6.2": (2011, 9),
            "6.3": (2012, 10),
            "10.0": (2014, 6),
        }

        if "pe" not in self.results.get("static", {}):
            return False

        compiletime = datetime.strptime(self.results["static"]["pe"]["timestamp"], "%Y-%m-%d %H:%M:%S")
        osver = self.results["static"]["pe"]["osversion"]
        osmajor = int(osver.split(".")[0], 10)
        if osmajor < 4 and compiletime.year >= 2000:
            self.data.append({"anomaly": "Minimum OS version is older than NT4 yet the PE timestamp year is newer than 2000"})
            self.ttps += ["T1099"]  # MITRE v6
            self.ttps += ["T1070"]  # MITRE v6,7,8
            self.ttps += ["T1070.006"]  # MITRE v7,8
            self.mbcs += ["OB0006", "F0005", "F0005.004"]
            self.weight += 1

        # throw out empty timestamps
        if compiletime.year > 1970 and osver in bad_date_map:
            if compiletime.year < bad_date_map[osver][0] or (
                compiletime.year == bad_date_map[osver][0] and compiletime.month < bad_date_map[osver][1]
            ):
                self.data.append(
                    {"anomaly": "Timestamp on binary predates the release date of the OS version it requires by at least a year"}
                )
                self.ttps += ["T1099"]  # MITRE v6
                self.ttps += ["T1070", "T1070.006"]  # MITRE v7,8
                self.mbcs += ["OB0006", "F0005", "F0005.004"]
                self.weight += 1

        if "sections" in self.results["static"]["pe"]:
            bigvirt = False
            unprint = False
            foundsec = None
            foundcodesec = False
            foundnamedupe = False
            lowrva = 0xFFFFFFFF
            imagebase = int(self.results["static"]["pe"]["imagebase"], 16)
            eprva = int(self.results["static"]["pe"]["entrypoint"], 16) - imagebase
            seennames = set()
            for section in self.results["static"]["pe"]["sections"]:
                if section["name"] in seennames:
                    foundnamedupe = True
                seennames.add(section["name"])
                if "IMAGE_SCN_CNT_CODE" in section["characteristics"]:
                    foundcodesec = True
                if "\\x" in section["name"]:
                    unprint = True
                secstart = int(section["virtual_address"], 16)
                secend = secstart + int(section["virtual_size"], 16)

                if (secend - secstart) >= 100 * 1024 * 1024:
                    bigvirt = True

                # seconds are mapped first to last, so the last section matched is the correct one
                if eprva >= secstart and eprva < secend:
                    foundsec = section
                if secstart < lowrva:
                    lowrva = secstart
            if foundnamedupe:
                self.data.append({"anomaly": "Found duplicated section names"})
                self.weight += 1
            if unprint:
                self.data.append({"anomaly": "Unprintable characters found in section name"})
                self.weight += 1
            if not foundsec and foundcodesec:
                # we check for code sections to not FP on resource-only DLLs where the EP RVA will be 0
                self.data.append({"anomaly": "Entrypoint of binary is located outside of any mapped sections"})
                self.weight += 1
            if foundsec and "IMAGE_SCN_MEM_EXECUTE" not in foundsec["characteristics"]:
                # Windows essentially turns DEP off in this case, but it was only seen (as far as named packers go) in
                # one instance I could think of years ago in a rare packer
                self.data.append({"anomaly": "Entrypoint of binary points to a non-executable code section"})
                self.weight += 1
            if bigvirt:
                # used to blow up memory dumpers
                self.data.append({"anomaly": "Contains a section with a virtual size >= 100MB"})
                self.weight += 1
        if "resources" in self.results["static"]["pe"]:
            for resource in self.results["static"]["pe"]["resources"]:
                if int(resource["size"], 16) >= 100 * 1024 * 1024:
                    self.data.append({"anomaly": "Contains a resource with a size >= 100MB"})
                    self.weight += 1

        if "versioninfo" in self.results["static"]["pe"]:
            for ver in self.results["static"]["pe"]["versioninfo"]:
                if (
                    ver["name"] == "OriginalFilename"
                    and ver["value"].lower().endswith(".dll")
                    and "PE32" in self.results.get("target", {})["file"].get("type", "")
                    and "DLL" not in self.results.get("target", {})["file"].get("type", "")
                ):
                    self.data.append(
                        {"anomaly": "OriginalFilename version info claims file is a DLL but binary is a main executable"}
                    )
                    self.weight += 1

        if "reported_checksum" in self.results["static"]["pe"] and "actual_checksum" in self.results["static"]["pe"]:
            reported = int(self.results["static"]["pe"]["reported_checksum"], 16)
            actual = int(self.results["static"]["pe"]["actual_checksum"], 16)
            if reported and reported != actual:
                self.data.append({"anomaly": "Actual checksum does not match that reported in PE header"})
                self.weight += 1

        if self.weight:
            return True
        return False


class StaticPEPDBPath(Signature):
    name = "static_pe_pdbpath"
    description = "The PE file contains a PDB path"
    severity = 1
    confidence = 80
    weight = 1
    categories = ["static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    references = [
        "https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html"
    ]

    def run(self):
        ret = False
        suspiciousnames = [
            "attack",
            "backdoor",
            "bind",
            "bypass",
            "downloader",
            "dropper",
            "exploit",
            "fake",
            "fuck",
            "hack",
            "hide",
            "hook",
            "inject",
            "keylog",
            "payload",
            "ransom",
            "shell",
            "spy",
            "trojan",
        ]

        devterms = [
            "consoleapplication",
            "windowsApplication",
            "windowsformsapplication",
            "visual studio ",
            "\\desktop",
            "\\users",
            "\\new folder",
            "- copy",
        ]

        pdbpath = self.results.get("static", {}).get("pe", {}).get("pdbpath", "")
        if pdbpath:
            for suspiciousname in suspiciousnames:
                if suspiciousname in pdbpath.lower():
                    if self.severity != 3:
                        self.severity = 3
                    self.data.append({"anomaly": "the pdb path contains a suspicious string"})
                    self.description = "The PE file contains a suspicious PDB path"
                    break

            for devterm in devterms:
                if devterm in pdbpath.lower():
                    if self.severity != 2 and self.severity != 3:
                        self.severity = 2
                    self.data.append(
                        {
                            "anomaly": "the pdb path contains a reference to a development path or term that may suggest a non-enterprise environment development/compilation"
                        }
                    )
                    self.description = "The PE file contains a suspicious PDB path"
                    break

            regex = re.compile("[a-zA-Z]:\\\\[\x00-\xFF]{0,500}[^\x00-\x7F]{1,}[\x00-\xFF]{0,500}\.pdb")
            if re.match(regex, pdbpath):
                if self.severity != 2 and self.severity != 3:
                    self.severity = 2
                self.data.append({"anomaly": "the pdb path contains non-ascii characters"})
                self.description = "The PE file contains a suspicious PDB path"

            self.data.append({"pdbpath": pdbpath})
            ret = True

        return ret


class PECompileTimeStomping(Signature):
    name = "pe_compile_timestomping"
    description = "Binary compilation timestomping detected"
    severity = 3
    categories = ["generic"]
    authors = ["ditekshen"]
    minimum = "1.3"
    ttps = ["T1099"]  # MITRE v6
    ttps += ["T1070"]  # MITRE v6,7,8
    ttps += ["T1070.006"]  # MITRE v7,8
    mbcs = ["OB0006", "F0005", "F0005.004"]

    def run(self):
        rawcompiletime = self.results.get("static", {}).get("pe", {}).get("timestamp", "")
        if rawcompiletime:
            compiletime = datetime.strptime(rawcompiletime, "%Y-%m-%d %H:%M:%S")
            currentyear = datetime.now().year
            currentmonth = datetime.now().month
            if compiletime.year > currentyear:
                self.data.append({"anomaly": "Compilation timestamp is in the future"})
                return True
            elif compiletime.year == currentyear and compiletime.month > currentmonth:
                self.data.append({"anomaly": "Compilation timestamp is in the future"})
                return True

        return False
