# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from types import SimpleNamespace

import olefile

from lib.cuckoo.common import trim_utils


def test_trim_doc_closes_ole_handle_and_uses_sector_size(monkeypatch, tmp_path):
    sample = tmp_path / "bloated.doc"
    sample.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64)

    closed = {"count": 0}

    class FakeOleFileIO:
        def __init__(self, filename):
            self.sector_size = 512
            self.num_fat_sectors = 1
            self._filesize = 1024 * 1024
            self.fat = [0, 1, 2, olefile.FREESECT, olefile.FREESECT]

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            closed["count"] += 1
            return False

    monkeypatch.setattr(trim_utils, "olefile", SimpleNamespace(OleFileIO=FakeOleFileIO, FREESECT=olefile.FREESECT))

    trimmed_size = trim_utils.trim_doc(str(sample).encode())
    assert trimmed_size == 512 * (2 + 2)
    assert closed["count"] == 1
