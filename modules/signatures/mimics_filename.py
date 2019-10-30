# Copyright (C) 2015 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import re2 as re
except:
    import re

from lib.cuckoo.common.abstracts import Signature

class MimicsExtension(Signature):
    name = "mimics_extension"
    description = ("Attempts to mimic the file extension of a {1} by having "
                   "'{0}' in the file name.")
    severity = 2
    categories = ["stealth"]
    authors = ["KillerInstinct"]
    minimum = "0.5"

    def run(self):
        # There are more, but these are the only ones I've observed
        execs = [
            "exe",
            "scr",
        ]
        exts = {
            "doc": "Word 97-2003 document",
            "docx": "Word 2007+ document",
            "xls": "Excel 97-2003 spreadsheet",
            "xlsx": "Excel 2007+ spreadsheet",
            "ppt": "PowerPoint 97-2003 file",
            "pptx": "PowerPoint 2007+ file",
            "jpeg": "JPEG image",
            "jpg": "JPG image",
            "png": "PNG image",
            "gif": "GIF image",
            "pdf": "PDF document",
            "xml": "XML document",
        }
        pat = ".*[ _\-\.](?P<FakeExtension>{0})\.(?:{1})".format(
            "|".join(exts.keys()), "|".join(execs))
        if self.results["target"]["category"] == "file":
            check = re.match(pat, self.results["target"]["file"]["name"])
            if check:
                ext = check.group("FakeExtension")
                self.description = self.description.format(ext,
                                                           exts[ext.lower()])
                return True

        return False
