# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
from subprocess import PIPE, Popen

from lib.cuckoo.common.utils import convert_to_printable, store_temp_file

log = logging.getLogger(__name__)


class Java(object):
    """Java Static Analysis"""

    def __init__(self, file_path, decomp_jar):
        self.file_path = file_path
        self.decomp_jar = decomp_jar

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None

        results = {}

        results["java"] = {}

        if self.decomp_jar:
            with open(self.file_path, "rb") as f:
                data = f.read()
            jar_file = store_temp_file(data, "decompile.jar")

            try:
                if self.decomp_jar.endswith(".jar"):
                    p = Popen(["java", "-jar", self.decomp_jar, jar_file], stdout=PIPE)
                else:
                    p = Popen([self.decomp_jar, jar_file], stdout=PIPE)
                results["java"]["decompiled"] = convert_to_printable(p.stdout.read())
            except Exception as e:
                log.error(e, exc_info=True)
                pass

            try:
                os.unlink(jar_file)
            except Exception:
                pass

        return results
