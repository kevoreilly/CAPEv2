# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import zlib

try:
    import olefile

    HAVE_OLEFILE = True
except ImportError:
    HAVE_OLEFILE = False
    print("Missed olefile dependency: pip3 install olefile")


log = logging.getLogger(__name__)


class HwpDocument(object):
    """Static analysis of HWP documents."""

    def __init__(self, filepath, results):
        self.filepath = filepath
        self.files = {}
        # self.ex = ExtractManager.for_task(task_id)

    def unpack_hwp(self):
        """Unpacks ole-based zip files."""
        ole = olefile.OleFileIO(self.filepath)
        streams = ole.listdir()
        for stream in streams:
            stream_name = "/".join(stream)
        # content = ole.openstream(stream).read()
        try:
            stream_content = zlib.decompress(ole.openstream(stream).read(), -15)
            self.files[stream_name] = stream_content
        except Exception as e:
            log.error(e, exc_info=True)
        ole.close()

    def extract_eps(self):
        """Extract some information from Encapsulated Post Script files."""
        ret = []
        for filename, content in self.files.items():
            if filename.lower().endswith(".eps") or filename.lower().endswith(".ps"):
                ret.append(content)
        return ret

    def run(self):
        self.unpack_hwp()

        self.ex.peek_office(self.files)

        return {"eps": self.extract_eps()}
