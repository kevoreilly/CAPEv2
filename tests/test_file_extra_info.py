# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import tempfile

import pytest

from lib.cuckoo.common.integrations import file_extra_info


class TestFileExtraInfo:
    def test_generic_file_extractors(self):
        results = {}
        data_dictionary = {"type": "MSI Installer"}
        options_dict = {}
        tmpdir = tempfile.mkdtemp()
        duplicated = {"sha256": set()}
        file_extra_info.generic_file_extractors(
            "tests/data/selfextraction/0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi",
            tmpdir,
            data_dictionary,
            options_dict,
            results,
            duplicated,
            tests=True,
        )
        assert data_dictionary["extracted_files_tool"] == "MsiExtract"
        assert len(data_dictionary["extracted_files"]) == 4

    def test_generic_file_extractors_no_tests(self):
        results = {}
        data_dictionary = {"die": ["Inno Setup"], "type": ""}
        options_dict = {}
        tmpdir = tempfile.mkdtemp()
        duplicated = {"sha256": set()}
        file_extra_info.generic_file_extractors(
            "tests/data/selfextraction/5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno",
            tmpdir,
            data_dictionary,
            options_dict,
            results,
            duplicated,
        )
        assert data_dictionary["extracted_files_tool"] == "InnoExtract"
        assert len(data_dictionary["extracted_files"]) == 1

    @pytest.mark.skip(reason="Not implemented yet")
    def test_batch_extract(self):
        extracted_files = file_extra_info.batch_extract(
            file="tests/data/selfextraction/",
        )
        assert len(extracted_files["result"]["extracted_files"]) == 4

    def test_vbe_extract(self):
        extracted_files = file_extra_info.vbe_extract(
            file="tests/data/selfextraction/c738cdd8ec0d65769e17eed1d6fe371893a2972b7a432c6532446d225e166733.vbe",
        )
        assert len(extracted_files["result"]["extracted_files"]) == 1

    @pytest.mark.skip(reason="Not implemented yet")
    def test_eziriz_deobfuscate(self):
        extracted_files = file_extra_info.eziriz_deobfuscate(
            file="tests/data/selfextraction/",
            data_dictionary={"die": ["Eziriz .NET Reactor"]} ** {"test": True, "options": {}},
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    @pytest.mark.skip(reason="Not implemented yet")
    def test_de4dot_deobfuscate(self):
        extracted_files = file_extra_info.de4dot_deobfuscate(
            file="tests/data/selfextraction/", filetype="Mono", **{"test": True, "options": {}}
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    def test_msi_extract(self):
        extracted_files = file_extra_info.msi_extract(
            file="tests/data/selfextraction/0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi",
            filetype="MSI Installer",
            **{"tests": True, "options": {}}
        )
        assert len(extracted_files["result"]["extracted_files"]) == 4

    def test_Inno_extract(self):
        extracted_files = file_extra_info.Inno_extract(
            file="tests/data/selfextraction/5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno",
            data_dictionary={"die": ["Inno Setup"]},
        )
        assert len(extracted_files["result"]["extracted_files"]) == 1
        assert extracted_files["result"]["extracted_files"] == ["app/vcfconv.exe"]

    @pytest.mark.skip(reason="Not implemented yet - need to include community repo")
    def test_kixtart_extract(self):
        extracted_files = file_extra_info.kixtart_extract(
            file="tests/data/selfextraction/d0d415dbe02e893fb1b2d6112c0f38d8ce65ab3268c896bfc64ba06096d4d09a.kix",
        )
        assert len(extracted_files["result"]["extracted_files"]) == 4

    @pytest.mark.skip(reason="Not implemented yet")
    def test_UnAutoIt_extract(self):
        extracted_files = file_extra_info.kixtart_extract(
            file="tests/data/selfextraction/5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno",
            data_dictionary={"yara": [{"name": "AutoIT_Compiled"}]},
            **{"test": True, "options": {}}
        )
        assert len(extracted_files["result"]["extracted_files"]) == 4

    def test_UPX_unpack(self):
        extracted_files = file_extra_info.UPX_unpack(
            file="tests/data/selfextraction/1b0c4149df7892b2497c955dc393ed49e458062324a81288589b15492ce8b50b.upx",
            filetype="UPX compressed",
            data_dictionary={},
            **{"test": True, "options": {}}
        )
        assert len(extracted_files["result"]["extracted_files"]) == 1
        assert extracted_files["result"]["extracted_files"] == [
            "1b0c4149df7892b2497c955dc393ed49e458062324a81288589b15492ce8b50b.upx_unpacked"
        ]

    def test_SevenZip_unpack(self):
        extracted_files = file_extra_info.SevenZip_unpack(
            file="tests/data/selfextraction/ab77ea6ad4b6766e0db88d4f49c2c0075ba18b3573d7c6d07ee878bd6e71c388.7z",
            data_dictionary={"die": ["7-zip Installer data"]},
            filetype="",
            **{"test": True, "options": {}}
        )
        assert len(extracted_files["result"]["extracted_files"]) == 6
        assert sorted(extracted_files["result"]["extracted_files"]) == [
            "Leggimi.txt",
            "Lisezmoi.txt",
            "Re-LoaderByR@1n.exe",
            "Readme.txt",
            "SetupComplete.cmd",
            "自述.txt",
        ]

    def test_RarSFX_extract(self):
        extracted_files = file_extra_info.RarSFX_extract(
            file="tests/data/selfextraction/9e69c36d967afbb1a948a022fcfb1a6384b35b233a47e7d859145db19018d21e.sfx",
            data_dictionary={"type": "RAR self-extracting archive"},
            options={},
        )
        assert len(extracted_files["result"]["extracted_files"]) == 3
        assert sorted(extracted_files["result"]["extracted_files"]) == ["Manag.exe", "mLib.cs", "x64.xr"]

    def test_office_one_extract(self):
        extracted_files = file_extra_info.office_one(
            file="tests/data/selfextraction/12c4d9eddce807d10e3578fcf2918366def586ec374a35957880a65dbd467efc.one",
        )
        assert len(extracted_files["result"]["extracted_files"]) == 6
        assert sorted(extracted_files["result"]["extracted_files"]) == [
            "_0.extracted",
            "_1.extracted",
            "_2.extracted",
            "_3.extracted",
            "_4.extracted",
            "_5.extracted",
        ]
