# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import, print_function
import logging
import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.cape_utils import generic_file_extractors
from lib.cuckoo.common.integrations.parse_dotnet import DotNETExecutable
from lib.cuckoo.common.integrations.parse_java import Java
from lib.cuckoo.common.integrations.parse_lnk import LnkShortcut
from lib.cuckoo.common.integrations.parse_office import HAVE_OLETOOLS, Office
from lib.cuckoo.common.integrations.parse_pdf import PDF

# from lib.cuckoo.common.integrations.parse_pe import HAVE_PEFILE, PortableExecutable
from lib.cuckoo.common.integrations.parse_url import HAVE_WHOIS, URL
from lib.cuckoo.common.integrations.parse_wsf import EncodedScriptFile, WindowsScriptFile


# from lib.cuckoo.common.integrations.parse_elf import ELF

log = logging.getLogger(__name__)


class Static(Processing):
    """Static analysis."""

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        self.key = "static"
        static = {}

        if self.task["category"] in ("file", "static"):
            package = self.results.get("info", {}).get("package", "")

            thetype = File(self.file_path).get_type()
            if not HAVE_OLETOOLS and "Zip archive data, at least v2.0" in thetype and package in ("doc", "ppt", "xls", "pub"):
                log.info("Missed dependencies: pip3 install oletools")

            # We extract PE data in targetinfo.py in File(X).get_all()
            if (
                static
                and self.results.get("target", {}).get("file", {}).get("pe")
                and "Mono" in File(self.file_path).get_content_type()
            ):
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
            # It's possible to fool libmagic into thinking our 2007+ file is a zip.
            # So until we have static analysis for zip files, we can use oleid to fail us out silently,
            # yeilding no static analysis results for actual zip files.
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
