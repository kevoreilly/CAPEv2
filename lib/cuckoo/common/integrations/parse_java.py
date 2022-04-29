# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import logging
import os
from subprocess import PIPE, Popen
from typing import Any, Dict

from lib.cuckoo.common.utils import convert_to_printable, store_temp_file

log = logging.getLogger(__name__)


class Java:
    """Java Static Analysis"""

    def __init__(self, file_path: str, decomp_jar: str):
        self.file_path = file_path
        self.decomp_jar = decomp_jar

    def run(self) -> Dict[str, Any]:
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            return None

        results = {"java": {}}

        if self.decomp_jar:
            with open(self.file_path, "rb") as f:
                data = f.read()
            jar_file = store_temp_file(data, "decompile.jar")

            try:
                if self.decomp_jar.endswith(".jar"):
                    p = Popen(["java", "-jar", self.decomp_jar, jar_file], stdout=PIPE)
                else:
                    p = Popen([self.decomp_jar, jar_file], stdout=PIPE)
                results["decompiled"] = convert_to_printable(p.stdout.read())
            except Exception as e:
                log.error(e, exc_info=True)

            with contextlib.suppress(Exception):
                os.unlink(jar_file)
        return results
