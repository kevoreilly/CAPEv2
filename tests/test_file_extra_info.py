# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import unittest

from lib.cuckoo.common.integrations import file_extra_info


class TestMsiExtract(unittest.TestCase):
    def test_msi_extract(self):
        extracted_files = file_extra_info.msi_extract(
            file="CAPE-TestFiles/selfextraction/0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi",
            filetype="MSI Installer",
            **{"test": True, "options": {}}
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")
