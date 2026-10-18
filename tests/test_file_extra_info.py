# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import pathlib
import tempfile

import pytest

from lib.cuckoo.common.integrations import file_extra_info
from lib.cuckoo.common.integrations.file_extra_info_modules.msi_extract import extract_details as msi_extract


@pytest.fixture(autouse=True)
def set_tools_folder():
    file_extra_info.tools_folder = "/tmp"
    yield


self_extraction_dir = pathlib.Path(__file__).parent / "data" / "selfextraction"


@pytest.mark.skipif(not (self_extraction_dir).exists(), reason="Required data file is not present")
class TestFileExtraInfo:
    @pytest.mark.skipif(
        not (self_extraction_dir / "0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi").exists(),
        reason="Required data file is not present",
    )
    def test_generic_file_extractors(self):
        results = {}
        data_dictionary = {"type": "MSI Installer"}
        options_dict = {}
        tmpdir = tempfile.mkdtemp()
        duplicated = {"sha256": set()}
        file_extra_info.generic_file_extractors(
            f"{self_extraction_dir}/0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi",
            tmpdir,
            data_dictionary,
            options_dict,
            results,
            duplicated,
            tests=True,
        )
        assert "MsiExtract" in data_dictionary["selfextract"].keys()
        assert len(data_dictionary["selfextract"]["MsiExtract"]["extracted_files"]) == 2

    @pytest.mark.skipif(
        not (self_extraction_dir / "5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno").exists(),
        reason="Required data file is not present",
    )
    @pytest.mark.skip(reason="innoextractor in community repo now")
    def test_generic_file_extractors_no_tests(self):
        results = {}
        data_dictionary = {"die": ["Inno Setup"], "type": ""}
        options_dict = {}
        tmpdir = tempfile.mkdtemp()
        duplicated = {"sha256": set()}
        file_extra_info.generic_file_extractors(
            f"{self_extraction_dir}/5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno",
            tmpdir,
            data_dictionary,
            options_dict,
            results,
            duplicated,
        )
        assert "InnoExtract" in data_dictionary["selfextract"].keys()
        assert len(data_dictionary["selfextract"]["InnoExtract"]["extracted_files"]) == 1

    @pytest.mark.skip(reason="Not implemented yet")
    def test_batch_extract(self):
        extracted_files = file_extra_info.batch_extract(
            file=f"{self_extraction_dir}/",
        )
        assert len(extracted_files["result"]["extracted_files"]) == 4

    @pytest.mark.skipif(
        not (self_extraction_dir / "c738cdd8ec0d65769e17eed1d6fe371893a2972b7a432c6532446d225e166733.vbe").exists(),
        reason="Required data file is not present",
    )
    def test_vbe_extract(self):
        extracted_files = file_extra_info.vbe_extract(
            file=f"{self_extraction_dir}/c738cdd8ec0d65769e17eed1d6fe371893a2972b7a432c6532446d225e166733.vbe",
        )
        assert len(extracted_files["result"]["extracted_files"]) == 1

    @pytest.mark.skip(reason="Not implemented yet")
    def test_eziriz_deobfuscate(self):
        extracted_files = file_extra_info.eziriz_deobfuscate(
            file=f"{self_extraction_dir}/",
            data_dictionary={"die": ["Eziriz .NET Reactor"]} ** {"test": True, "options": {}},
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    @pytest.mark.skip(reason="Not implemented yet")
    def test_de4dot_deobfuscate(self):
        extracted_files = file_extra_info.de4dot_deobfuscate(
            file=f"{self_extraction_dir}/", filetype="Mono", **{"test": True, "options": {}}
        )
        self.assertEqual(len(extracted_files["result"]["extracted_files"]), 4, "Failed to extract.")

    @pytest.mark.skipif(
        not (self_extraction_dir / "0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi").exists(),
        reason="Required data file is not present",
    )
    def test_msi_extract(self):
        extracted_files = msi_extract(
            file=f"{self_extraction_dir}/0ea5e25b12ab314bc9a0569c3ca756f205f40b792119f8e0fc62c874628dfea0.msi",
            filetype="MSI Installer",
            **{"tests": True, "options": {}},
        )
        assert len(extracted_files["result"]["extracted_files"]) == 2

    @pytest.mark.skipif(
        not (self_extraction_dir / "5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno").exists(),
        reason="Required data file is not present",
    )
    @pytest.mark.skip(reason="innoextractor in community repo now")
    def test_Inno_extract(self):
        extracted_files = file_extra_info.Inno_extract(
            file=f"{self_extraction_dir}/5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno",
            data_dictionary={"die": ["Inno Setup"]},
        )
        assert len(extracted_files["result"]["extracted_files"]) == 1
        assert extracted_files["result"]["extracted_files"] == ["app/vcfconv.exe"]

    @pytest.mark.skip(reason="Not implemented yet - need to include community repo")
    def test_kixtart_extract(self):
        extracted_files = file_extra_info.kixtart_extract(
            file=f"{self_extraction_dir}/d0d415dbe02e893fb1b2d6112c0f38d8ce65ab3268c896bfc64ba06096d4d09a.kix",
        )
        assert len(extracted_files["result"]["extracted_files"]) == 4

    @pytest.mark.skip(reason="Not implemented yet")
    def test_UnAutoIt_extract(self):
        extracted_files = file_extra_info.kixtart_extract(
            file=f"{self_extraction_dir}/5b354397f6393ed777639b7d40dec3f37215dcb5078c63993e8a9703e819e2bc.inno",
            data_dictionary={"yara": [{"name": "AutoIT_Compiled"}]},
            **{"test": True, "options": {}},
        )
        assert len(extracted_files["result"]["extracted_files"]) == 4

    @pytest.mark.skipif(
        not (self_extraction_dir / "1b0c4149df7892b2497c955dc393ed49e458062324a81288589b15492ce8b50b.upx").exists(),
        reason="Required data file is not present",
    )
    def test_UPX_unpack(self):
        extracted_files = file_extra_info.UPX_unpack(
            file=f"{self_extraction_dir}/1b0c4149df7892b2497c955dc393ed49e458062324a81288589b15492ce8b50b.upx",
            filetype="UPX compressed",
            data_dictionary={},
            **{"test": True, "options": {}},
        )
        assert len(extracted_files["result"]["extracted_files"]) == 1
        assert extracted_files["result"]["extracted_files"] == [
            "1b0c4149df7892b2497c955dc393ed49e458062324a81288589b15492ce8b50b.upx_unpacked"
        ]

    @pytest.mark.skipif(
        not (self_extraction_dir / "ab77ea6ad4b6766e0db88d4f49c2c0075ba18b3573d7c6d07ee878bd6e71c388.7z").exists(),
        reason="Required data file is not present",
    )
    def test_SevenZip_unpack(self):
        extracted_files = file_extra_info.SevenZip_unpack(
            file=f"{self_extraction_dir}/ab77ea6ad4b6766e0db88d4f49c2c0075ba18b3573d7c6d07ee878bd6e71c388.7z",
            data_dictionary={"die": ["7-zip Installer data"]},
            filetype="",
            **{"test": True, "options": {}},
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

    @pytest.mark.skipif(
        not (self_extraction_dir / "9e69c36d967afbb1a948a022fcfb1a6384b35b233a47e7d859145db19018d21e.sfx").exists(),
        reason="Required data file is not present",
    )
    def test_RarSFX_extract(self):
        extracted_files = file_extra_info.RarSFX_extract(
            file=f"{self_extraction_dir}/9e69c36d967afbb1a948a022fcfb1a6384b35b233a47e7d859145db19018d21e.sfx",
            data_dictionary={"type": "RAR self-extracting archive"},
            options={},
        )
        assert len(extracted_files["result"]["extracted_files"]) == 3
        assert sorted(extracted_files["result"]["extracted_files"]) == ["Manag.exe", "mLib.cs", "x64.xr"]

    @pytest.mark.skipif(
        not (self_extraction_dir / "12c4d9eddce807d10e3578fcf2918366def586ec374a35957880a65dbd467efc.one").exists(),
        reason="Required data file is not present",
    )
    def test_office_one_extract(self):
        extracted_files = file_extra_info.office_one(
            file=f"{self_extraction_dir}/12c4d9eddce807d10e3578fcf2918366def586ec374a35957880a65dbd467efc.one",
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


def test_run_tool_non_utf8_stdout():
    """Verify run_tool with universal_newlines=True replaces invalid UTF-8 bytes instead of raising UnicodeDecodeError."""
    import subprocess
    import sys
    from lib.cuckoo.common.integrations.utils import run_tool

    output = run_tool(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'extracting \\xa8\\xff_file.bin\\n')"],
        universal_newlines=True,
        stderr=subprocess.PIPE,
    )
    assert isinstance(output, str)
    assert "extracting " in output
    assert "_file.bin" in output


def test_collect_extracted_filenames_sanitizes_surrogate_names(tmp_path):
    """Verify collect_extracted_filenames renames files with surrogate-escaped non-UTF-8 bytes so downstream tools and JSON serializers get valid UTF-8 paths."""
    import os
    from lib.cuckoo.common.integrations.file_extra_info_modules import collect_extracted_filenames

    raw_dir = os.fsencode(str(tmp_path))
    non_utf8_name = b"\x8f\xe0\xae\xe7\xa8_readme.txt"
    with open(os.path.join(raw_dir, non_utf8_name), "wb") as f:
        f.write(b"payload")

    extracted = collect_extracted_filenames(str(tmp_path))
    assert len(extracted) == 1
    assert extracted[0].encode("utf-8")
    assert (tmp_path / extracted[0]).is_file()


def test_detect_it_easy_info_calledprocesserror_with_surrogate_path(monkeypatch):
    """Verify detect_it_easy_info logs CalledProcessError safely even when file_path contains lone surrogates."""
    import io
    import logging
    import subprocess

    monkeypatch.setattr(file_extra_info, "path_exists", lambda _: True)

    def raise_cpe(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd, output="Cannot find file\n")

    monkeypatch.setattr(subprocess, "check_output", raise_cpe)

    stream = io.BytesIO()
    text_stream = io.TextIOWrapper(stream, encoding="utf-8", errors="strict")
    handler = logging.StreamHandler(text_stream)
    file_extra_info.log.addHandler(handler)
    try:
        res = file_extra_info.detect_it_easy_info("/tmp/archive/\udc8f\udce0\udcae.txt")
        text_stream.flush()
    finally:
        file_extra_info.log.removeHandler(handler)

    assert res == []
    assert b"Detect-It-Easy: Failed to execute" in stream.getvalue()


def test_detect_it_easy_info_calledprocesserror_logs_warning_and_stderr(monkeypatch, caplog):
    """Verify detect_it_easy_info captures stderr via PIPE and logs CalledProcessError at WARNING with returncode."""
    import logging
    import subprocess

    monkeypatch.setattr(file_extra_info, "path_exists", lambda _: True)
    captured_kwargs = {}

    def raise_cpe(cmd, **kwargs):
        captured_kwargs.update(kwargs)
        raise subprocess.CalledProcessError(-11, cmd, output="", stderr="segmentation fault")

    monkeypatch.setattr(subprocess, "check_output", raise_cpe)

    with caplog.at_level(logging.WARNING, logger=file_extra_info.__name__):
        res = file_extra_info.detect_it_easy_info("/tmp/sample.bin")

    assert res == []
    assert captured_kwargs.get("stderr") == subprocess.PIPE
    assert any(
        r.levelno == logging.WARNING
        and "returncode=-11" in r.message
        and "stderr=`segmentation fault`" in r.message
        for r in caplog.records
    )
    assert not any(r.levelno >= logging.ERROR for r in caplog.records)



