# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import pytest

from lib.cuckoo.common.integrations import file_extra_info

"""
We need to cover all fileformarts so we need to find few files

0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi
9e69c36d967afbb1a948a022fcfb1a6384b35b233a47e7d859145db19018d21e.sfx
1b0c4149df7892b2497c955dc393ed49e458062324a81288589b15492ce8b50b.upx
ab77ea6ad4b6766e0db88d4f49c2c0075ba18b3573d7c6d07ee878bd6e71c388.7z
2f89716421e188bfa5a0ecaf1774da429ebe8ea26ff30ab7dca309627db43825.7z
da84979c7d5ada9fc590def8f40ba0172fb1ade21f144a26dbdfaa2198fa9e67.nsis
5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno
f0f451e9dc3054a32d195c88a2d98f88dc900d333de0fcdd2ea400e67519d280.7z
60b17976fd8d49c052f9d5254b0c9ff2738868942f17f6e6f03dda5e7c592eb3.cab

"""


class TestFileExtraInfo():
    @pytest.mark.skip(reason="Not implemented yet")
    def test_batch_extract(self):
        extracted_files = file_extra_info.msi_extract(
            file="tests/data/selfextraction/0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi",
            filetype="MSI Installer",
            **{"test": True, "options": {}}
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    @pytest.mark.skip(reason="Not implemented yet")
    def test_vbe_extract(self):
        extracted_files = file_extra_info.msi_extract(
            file="tests/data/selfextraction/0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi",
            filetype="MSI Installer",
            **{"test": True, "options": {}}
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    @pytest.mark.skip(reason="Not implemented yet")
    def test_eziriz_deobfuscate(self):
        extracted_files = file_extra_info.eziriz_deobfuscate(
            file="tests/data/selfextraction/0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi",
            data_dictionary={"die": ["Eziriz .NET Reactor"]} ** {"test": True, "options": {}},
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    @pytest.mark.skip(reason="Not implemented yet")
    def test_de4dot_deobfuscate(self):
        extracted_files = file_extra_info.de4dot_deobfuscate(
            file="tests/data/selfextraction/0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi",
            filetype="Mono",
            **{"test": True, "options": {}}
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    def test_msi_extract(self):
        extracted_files = file_extra_info.msi_extract(
            file="tests/data/selfextraction/0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi",
            filetype="MSI Installer",
            **{"test": True, "options": {}}
        )
        assert len(extracted_files["result"]["extracted_files"]) == 4

    def test_Inno_extract(self):
        extracted_files = file_extra_info.Inno_extract(
            file="tests/data/selfextraction/5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno",
            data_dictionary={"die": ["Inno Setup"]}
        )
        assert len(extracted_files["result"]["extracted_files"]) == 1
        assert extracted_files["result"]["extracted_files"] == ['app/vcfconv.exe']

    @pytest.mark.skip(reason="Not implemented yet")
    def test_kixtart_extract(self):
        extracted_files = file_extra_info.kixtart_extract(
            file="tests/data/selfextraction/5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno",
            filetype="MSI Installer",
            **{"test": True, "options": {}}
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    @pytest.mark.skip(reason="Not implemented yet")
    def test_UnAutoIt_extract(self):
        extracted_files = file_extra_info.kixtart_extract(
            file="tests/data/selfextraction/5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno",
            filetype="MSI Installer",
            **{"test": True, "options": {}}
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    @pytest.mark.skip(reason="Not implemented yet")
    def test_UPX_unpack(self):
        extracted_files = file_extra_info.UPX_unpack(
            file="tests/data/selfextraction/5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno",
            filetype="MSI Installer",
            **{"test": True, "options": {}}
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    @pytest.mark.skip(reason="Not implemented yet")
    def test_SevenZip_unpack(self):
        extracted_files = file_extra_info.SevenZip_unpack(
            file="tests/data/selfextraction/ab77ea6ad4b6766e0db88d4f49c2c0075ba18b3573d7c6d07ee878bd6e71c388.7z",
            filetype="MSI Installer",
            **{"test": True, "options": {}}
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    def test_RarSFX_extract(self):
        extracted_files = file_extra_info.RarSFX_extract(
            file="tests/data/selfextraction/9e69c36d967afbb1a948a022fcfb1a6384b35b233a47e7d859145db19018d21e.sfx",
            data_dictionary={"type": "RAR self-extracting archive"},
            options = {},
        )
        assert len(extracted_files["result"]["extracted_files"]) == 3
        assert extracted_files["result"]["extracted_files"] == ['x64.xr', 'mLib.cs', 'Manag.exe']

    @pytest.mark.skip(reason="Not implemented yet")
    def test_office_one_extract(self):
        extracted_files = file_extra_info.msi_extract(
            file="tests/data/selfextraction/60b17976fd8d49c052f9d5254b0c9ff2738868942f17f6e6f03dda5e7c592eb3.cab",
            filetype="MSI Installer",
            **{"test": True, "options": {}}
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")
