# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import logging
from pathlib import Path
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
        p = Path(self.file_path)
        if not p.exists():
            return None

        results = {"java": {}}

        if self.decomp_jar:
            data = p.read_bytes()
            jar_file = store_temp_file(data, "decompile.jar")

            try:
                if self.decomp_jar.endswith(".jar"):
                    p = Popen(["java", "-jar", self.decomp_jar, jar_file], stdout=PIPE)
                else:
                    p = Popen([self.decomp_jar, jar_file], stdout=PIPE)
                results["decompiled"] = convert_to_printable(p.stdout.read())
            except Exception as e:
                log.exception(e)

            with contextlib.suppress(Exception):
                Path(jar_file.decode()).unlink()
        return results
