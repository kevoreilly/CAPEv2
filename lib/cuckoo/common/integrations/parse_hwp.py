# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import zlib
from typing import Dict, List

try:
    import olefile

    HAVE_OLEFILE = True
except ImportError:
    HAVE_OLEFILE = False
    print("Missed olefile dependency: pip3 install olefile")


log = logging.getLogger(__name__)


class HwpDocument:
    """Static analysis of HWP documents."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.files: Dict[str, bytes] = {}
        # self.ex = ExtractManager.for_task(task_id)

    def unpack_hwp(self):
        """Unpacks ole-based zip files."""
        with olefile.OleFileIO(self.filepath) as ole:
            streams = ole.listdir()
            for stream in streams:
                stream_name = "/".join(stream)
            try:
                with ole.openstream(stream) as f:
                    contents = f.read()
                stream_content = zlib.decompress(contents, -15)
                self.files[stream_name] = stream_content
            except Exception as e:
                log.exception(e)

    def extract_eps(self) -> List[bytes]:
        """Extract some information from Encapsulated Post Script files."""
        return [content for filename, content in self.files.items() if filename.lower().endswith((".eps", ".ps"))]

    def run(self) -> Dict[str, List[bytes]]:
        self.unpack_hwp()
        self.ex.peek_office(self.files)
        return {"eps": self.extract_eps()}
