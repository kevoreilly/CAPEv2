from __future__ import absolute_import
from __future__ import print_function
import re
import sys

"""
rule pony {
    meta:
        author = "adam"
        description = "Detect pony"

    strings:
        $s1 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
        $s2 = "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0"

    condition:
        $s1 and $s2
}
"""


def config(memdump_path, read=False):
    res = False
    try:
        if read:
            F = open(memdump_path, "rb").read()
        else:
            F = memdump_path
        """
        # Get the   aPLib header + data
        buf = re.findall(r"aPLib .*PWDFILE", cData, re.DOTALL|re.MULTILINE)
        # Strip out the header
        if buf and len(buf[0]) > 200:
            cData = buf[0][200:]
        """
        artifacts_raw = {
            "controllers": [],
            "downloads": [],
        }

        start = F.find("YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0")
        if start:
            F = F[start - 600 : start + 500]

        gate_url = re.compile(".*\.php$")
        exe_url = re.compile(".*\.exe$")
        dll_url = re.compile(".*\.dll$")
        output = re.findall("(https?:\/\/.[A-Za-z0-9-\.\_\~\:\/\?\#\[\]\@\!\$\&'\(\)\*\+\,\;\\=]+(?:\.php|\.exe|\.dll))", F)
        for url in output:
            try:
                if "\x00" not in url:
                    # url = self._check_valid_url(url)
                    if url is None:
                        continue
                    if gate_url.match(url):
                        artifacts_raw["controllers"].append(url.lower())
                    elif exe_url.match(url):
                        artifacts_raw["downloads"].append(url.lower())
                    elif dll_url.match(url):
                        artifacts_raw["downloads"].append(url.lower())
            except Exception as e:
                print(e, sys.exc_info())
        artifacts_raw["controllers"] = list(set(artifacts_raw["controllers"]))
        artifacts_raw["downloads"] = list(set(artifacts_raw["downloads"]))
        if len(artifacts_raw["controllers"]) != 0 or len(artifacts_raw["downloads"]) != 0:
            res = artifacts_raw
    except Exception as e:
        print(e, sys.exc_info())

    return res


if __name__ == "__main__":
    res = config(sys.argv[1])
    print(res)
