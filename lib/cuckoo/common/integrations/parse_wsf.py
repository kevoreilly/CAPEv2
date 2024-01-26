# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from pathlib import Path
from typing import List

from lib.cuckoo.common.integrations.parse_encoded_script import EncodedScriptFile

try:
    import re2 as re
except ImportError:
    import re

try:
    import bs4

    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False


class WindowsScriptFile:
    script_re = "<\\s*script\\s*.*>.*?<\\s*/\\s*script\\s*>"

    def __init__(self, filepath):
        self.filepath = filepath

    def run(self) -> List[str]:
        ret = []
        try:
            source = Path(self.filepath).read_text()
        except UnicodeDecodeError:
            return ret

        # Get rid of superfluous comments.
        source = re.sub("/\\*.*?\\*/", "", source, flags=re.S)

        for script in re.findall(self.script_re, source, re.I | re.S):
            try:
                x = bs4.BeautifulSoup(script, "html.parser")
                language = x.script.attrs.get("language", "").lower()
            except Exception:
                language = None

            # We can't rely on bs4 or any other HTML/XML parser to provide us
            # with the raw content of the xml tag as they decode html entities
            # and all that, leaving us with a corrupted string.
            source = re.match("<.*>(.*)</.*>$", script, re.S).group(0)

            # Decode JScript.Encode encoding.
            if language in {"jscript.encode", "vbscript.encode"}:
                source = EncodedScriptFile(self.filepath).decode(source.encode())

            if len(source) > 65536:
                source = f"{source[:65536]}\r\n<truncated>"

            ret.append(source)

        return ret
