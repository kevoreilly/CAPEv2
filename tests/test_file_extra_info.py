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


@pytest.mark.parametrize("as_directories", [False, True])
def test_collect_extracted_filenames_preserves_sanitized_name_collisions(tmp_path, as_directories):
    """Verify colliding sanitized names remain distinct and all extracted content is retained."""
    import os
    from lib.cuckoo.common.integrations.file_extra_info_modules import collect_extracted_filenames

    raw_dir = os.fsencode(str(tmp_path))
    names = (b"\xff.exe", b"\xfe.exe", b"?.exe")
    payloads = (b"first", b"second", b"existing")
    for name, payload in zip(names, payloads):
        if as_directories:
            directory = os.path.join(raw_dir, name[:-4])
            os.makedirs(directory)
            with open(os.path.join(directory, b"payload.bin"), "wb") as f:
                f.write(payload)
        else:
            with open(os.path.join(raw_dir, name), "wb") as f:
                f.write(payload)

    extracted = collect_extracted_filenames(str(tmp_path))

    assert len(extracted) == 3
    assert len(set(extracted)) == 3
    assert all(path.encode("utf-8") for path in extracted)
    assert all((tmp_path / path).is_file() for path in extracted)
    contents = {(tmp_path / path).read_bytes() for path in extracted}
    assert contents == set(payloads)


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


def test_get_files_storage_path_and_deduplicate(tmp_path, monkeypatch):
    import hashlib
    import os
    import time
    from lib.cuckoo.common import utils as cuckoo_utils

    monkeypatch.setattr(cuckoo_utils, "CUCKOO_ROOT", str(tmp_path))
    payload = b"sharded-dedup-test-payload"
    sha256 = hashlib.sha256(payload).hexdigest()

    with pytest.raises(ValueError):
        cuckoo_utils.get_files_storage_path("../outside")

    sharded = cuckoo_utils.get_files_storage_path(sha256)
    assert sharded == str(tmp_path / "storage" / "files" / sha256[:2] / sha256[2:4] / sha256)

    # Legacy flat path takes precedence when present
    flat_dir = tmp_path / "storage" / "files"
    flat_dir.mkdir(parents=True)
    flat_file = flat_dir / sha256
    flat_file.write_bytes(payload)
    assert cuckoo_utils.get_files_storage_path(sha256) == str(flat_file)
    flat_file.unlink()

    # In-place deduplication replaces regular file with symlink to sharded master
    analysis_drop = tmp_path / "storage" / "analyses" / "1" / "files" / sha256
    analysis_drop.parent.mkdir(parents=True)
    analysis_drop.write_bytes(payload)
    master = cuckoo_utils.deduplicate_file_to_storage(str(analysis_drop), sha256)
    assert master == sharded
    assert os.path.isfile(master)
    assert os.path.islink(analysis_drop)
    assert os.readlink(analysis_drop) == master
    assert analysis_drop.read_bytes() == payload

    # Re-deduplicating when master exists refreshes mtime and replaces broken symlink at dest
    old_time = time.time() - 7200
    os.utime(master, (old_time, old_time))
    src_tmp = tmp_path / "tmp_extracted.bin"
    src_tmp.write_bytes(payload)
    dest_link = tmp_path / "storage" / "analyses" / "2" / "selfextracted" / sha256
    dest_link.parent.mkdir(parents=True)
    os.symlink(str(tmp_path / "nonexistent_target"), str(dest_link))

    cuckoo_utils.deduplicate_file_to_storage(str(src_tmp), sha256, str(dest_link))
    assert not src_tmp.exists()
    assert os.path.islink(dest_link)
    assert os.readlink(dest_link) == master
    assert os.stat(master).st_mtime > old_time + 3600


def test_extracted_files_metadata_deduplicates_and_writes_relative_path(tmp_path, monkeypatch):
    import hashlib
    import json
    import os
    from lib.cuckoo.common import utils as cuckoo_utils

    monkeypatch.setattr(cuckoo_utils, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(file_extra_info.processing_conf.trid, "enabled", False)
    monkeypatch.setattr(file_extra_info.processing_conf.die, "enabled", False)

    payload = b"self-extracted-content"
    sha256 = hashlib.sha256(payload).hexdigest()

    tempdir = tmp_path / "temp_extract"
    tempdir.mkdir()
    extracted_file = tempdir / "inner.bin"
    extracted_file.write_bytes(payload)

    analysis_dir = tmp_path / "storage" / "analyses" / "10"
    dest_folder = analysis_dir / "selfextracted"
    dest_folder.mkdir(parents=True)
    files_json = analysis_dir / "files.json"

    results = {}
    meta = file_extra_info._extracted_files_metadata(
        str(tempdir),
        str(dest_folder),
        files=["inner.bin"],
        results=results,
    )
    assert len(meta) == 1
    dest_file = dest_folder / sha256
    assert os.path.islink(dest_file)
    assert dest_file.read_bytes() == payload

    lines = [json.loads(line) for line in files_json.read_text().splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0]["path"] == f"selfextracted/{sha256}"
    assert lines[0]["category"] == "selfextracted"
    assert os.path.join(str(analysis_dir), lines[0]["path"]) == str(dest_file)

    # Re-running with the same destination file already present must not append duplicate lines
    extracted_file_2 = tempdir / "inner.bin"
    extracted_file_2.write_bytes(payload)
    file_extra_info._extracted_files_metadata(
        str(tempdir),
        str(dest_folder),
        files=["inner.bin"],
        results=results,
    )
    lines_after = [json.loads(line) for line in files_json.read_text().splitlines() if line.strip()]
    assert len(lines_after) == 1


def test_files_clean_before_respects_nested_symlinks_and_prunes_shards(tmp_path, monkeypatch):
    import hashlib
    import os
    import time
    from lib.cuckoo.common import cleaners_utils, utils as cuckoo_utils

    monkeypatch.setattr(cuckoo_utils, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(cleaners_utils, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(cleaners_utils.repconf.mongodb, "enabled", False)

    sha_kept = hashlib.sha256(b"kept-by-nested-symlink").hexdigest()
    sha_old = hashlib.sha256(b"unreferenced-expired").hexdigest()

    src_kept = tmp_path / "kept.bin"
    src_kept.write_bytes(b"kept-by-nested-symlink")
    nested_link = tmp_path / "storage" / "analyses" / "5" / "package_files" / "sub" / sha_kept
    master_kept = cuckoo_utils.deduplicate_file_to_storage(str(src_kept), sha_kept, str(nested_link))

    src_old = tmp_path / "old.bin"
    src_old.write_bytes(b"unreferenced-expired")
    orphan_link = tmp_path / " orphan_link"
    master_old = cuckoo_utils.deduplicate_file_to_storage(str(src_old), sha_old, str(orphan_link))
    orphan_link.unlink()

    # Backdate master_old so mtime is older than 1s, while st_ctime on Linux stays current unless mocked
    past = time.time() - 86400
    monkeypatch.setattr(
        cleaners_utils,
        "path_get_date",
        lambda p, value="st_ctime": past if p == master_old else os.stat(p).st_mtime,
    )

    cleaners_utils.files_clean_before("1h")
    assert os.path.exists(master_kept)
    assert not os.path.exists(master_old)
    assert not os.path.exists(os.path.dirname(master_old))


@pytest.mark.skipif(
    __import__("sys").platform != "linux" or __import__("platform").machine() != "x86_64",
    reason="data/7zz is a Linux x86_64 binary",
)
def test_bundled_7zz_binary_and_sevenzip_unpack(tmp_path):
    import os
    import subprocess
    from lib.cuckoo.common.constants import CUCKOO_ROOT

    bundled_7zz = pathlib.Path(CUCKOO_ROOT) / "data" / "7zz"
    assert bundled_7zz.is_file()
    assert os.access(bundled_7zz, os.X_OK)

    payload_file = tmp_path / "sample.txt"
    payload_file.write_text("bundled 7zz extraction test\n", encoding="utf-8")
    archive_file = tmp_path / "sample.7z"
    subprocess.run(
        [str(bundled_7zz), "a", "-t7z", "-pinfected", "-y", str(archive_file), str(payload_file)],
        check=True,
        capture_output=True,
    )

    extracted = file_extra_info.SevenZip_unpack(
        file=str(archive_file),
        filetype="",
        data_dictionary={"die": ["7-zip Installer data"]},
        options={"password": "infected"},
        test=True,
    )
    assert extracted is not None
    assert extracted["result"]["extracted_files"] == ["sample.txt"]


@pytest.mark.parametrize(
    ("have_oletools", "office_enabled", "file_name", "file_type", "package", "expected_called"),
    [
        (False, True, "sample.doc", "Composite Document File", "doc", False),
        (True, False, "sample.doc", "Composite Document File", "doc", False),
        (True, True, "sample.docm", "Microsoft Word 2007+", "", True),
        (True, True, "sample.rtf", "ASCII text", "", True),
        (True, True, "blob.bin", "Rich Text Format data, version 1", "", True),
        (True, True, "a" * 64, "Microsoft Word 2007+", "", True),
        (True, True, "a" * 64, "Composite Document File V2 Document, MSI Installer", "", False),
        (True, True, "sample.xlsm", "Microsoft Excel 2007+", "", True),
        (True, True, "sample.pptm", "Microsoft PowerPoint 2007+", "", True),
        (True, True, ["dropped.docm"], "Microsoft Word 2007+", "", True),
        (True, True, "notes.txt", "ASCII text", "", False),
    ],
)
def test_static_file_info_office_guards_and_extensions(
    monkeypatch,
    tmp_path,
    have_oletools,
    office_enabled,
    file_name,
    file_type,
    package,
    expected_called,
):
    sample = tmp_path / "payload.bin"
    sample.write_bytes(b"test office bytes")
    called = []

    class FakeOffice:
        def __init__(self, file_path, task_id, sha256, options):
            called.append((file_path, task_id, sha256))
            self.extracted_files = []

        def run(self):
            return {"Metadata": {"HasMacros": "No"}}

    monkeypatch.setattr(file_extra_info, "HAVE_OLETOOLS", have_oletools)
    monkeypatch.setattr(file_extra_info.integration_conf.general, "office", office_enabled)
    monkeypatch.setattr(file_extra_info, "HAVE_MALCAT", False)
    monkeypatch.setattr(file_extra_info, "HAVE_PEFILE", False)
    monkeypatch.setattr(file_extra_info, "HAVE_FLOSS", False)
    monkeypatch.setattr(file_extra_info, "HAVE_STRINGS", False)
    monkeypatch.setattr(file_extra_info, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(file_extra_info.processing_conf.trid, "enabled", False)
    monkeypatch.setattr(file_extra_info.processing_conf.die, "enabled", False)
    monkeypatch.setattr(file_extra_info, "Office", FakeOffice)
    monkeypatch.setattr(file_extra_info, "generic_file_extractors", lambda *a, **k: None)

    data_dict = {"name": file_name, "type": file_type, "sha256": "a" * 64}
    file_extra_info.static_file_info(
        data_dict,
        str(sample),
        "12",
        package,
        "",
        str(tmp_path / "selfextracted"),
        {},
        {"sha256": set()},
    )
    assert bool(called) is expected_called


def test_static_file_info_bridges_office_extracted_files_to_selfextract(monkeypatch, tmp_path):
    from lib.cuckoo.common import utils as cuckoo_utils

    tools_dir = tmp_path / "tools"
    dest_folder = tmp_path / "storage" / "analyses" / "15" / "selfextracted"
    sample = tmp_path / "sample.rtf"
    sample.write_bytes(b"{\\rtf1}")

    payloads = [
        ("../../evil.exe", b"first-extracted-payload"),
        ("../../evil.exe", b"second-colliding-payload"),
        ("..", b"dotdot-fallback-payload"),
    ]

    class FakeOffice:
        def __init__(self, file_path, task_id, sha256, options):
            self.extracted_files = []

        def run(self):
            self.extracted_files = list(payloads)
            return {"rtf": {"1": [{"filename": "evil.exe"}]}}

    monkeypatch.setattr(cuckoo_utils, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(file_extra_info, "tools_folder", str(tools_dir))
    monkeypatch.setattr(file_extra_info, "HAVE_OLETOOLS", True)
    monkeypatch.setattr(file_extra_info.integration_conf.general, "office", True)
    monkeypatch.setattr(file_extra_info, "HAVE_MALCAT", False)
    monkeypatch.setattr(file_extra_info, "HAVE_PEFILE", False)
    monkeypatch.setattr(file_extra_info, "HAVE_FLOSS", False)
    monkeypatch.setattr(file_extra_info, "HAVE_STRINGS", False)
    monkeypatch.setattr(file_extra_info, "HAVE_VIRUSTOTAL", False)
    monkeypatch.setattr(file_extra_info.processing_conf.trid, "enabled", False)
    monkeypatch.setattr(file_extra_info.processing_conf.die, "enabled", False)
    monkeypatch.setattr(file_extra_info, "Office", FakeOffice)
    monkeypatch.setattr(file_extra_info, "generic_file_extractors", lambda *a, **k: None)

    data_dict = {"name": "sample.rtf", "type": "Rich Text Format", "sha256": "b" * 64}
    results = {}
    file_extra_info.static_file_info(
        data_dict,
        str(sample),
        "15",
        "",
        "password=infected",
        str(dest_folder),
        results,
        {"sha256": set()},
    )

    assert "Office" in data_dict.get("selfextract", {})
    office_selfextract = data_dict["selfextract"]["Office"]
    assert len(office_selfextract["extracted_files"]) == 3
    assert office_selfextract["password"] == "infected"
    assert office_selfextract["extracted_files_time"] >= 0
    # Tempdir under tools_folder must be cleaned up after metadata generation
    assert list(tools_dir.iterdir()) == []
    # Path traversal must not leave any artifacts outside tools_dir/dest_folder
    assert not (tmp_path / "evil.exe").exists()


def test_extractor_ctx_uses_cape_external_dir_by_default(tmp_path, monkeypatch):
    import os
    from lib.cuckoo.common.integrations.file_extra_info_modules import extractor_ctx

    ext_dir = tmp_path / "cape-external"
    explicit_dir = tmp_path / "explicit"
    monkeypatch.setattr("lib.cuckoo.common.integrations.file_extra_info_modules.get_cape_external_dir", lambda: str(ext_dir))

    with extractor_ctx("sample.bin", "unit_tool", prefix="u_", folder=None) as ctx:
        assert os.path.dirname(ctx["tempdir"]) == str(ext_dir)
        assert os.path.basename(ctx["tempdir"]).startswith("u_")

    with extractor_ctx("sample.bin", "unit_tool", prefix="e_", folder=str(explicit_dir)) as ctx:
        assert os.path.dirname(ctx["tempdir"]) == str(explicit_dir)
        assert os.path.basename(ctx["tempdir"]).startswith("e_")


@pytest.mark.parametrize(
    ("filename", "die_list"),
    [
        ("plain.exe", ["Microsoft Visual C#", "UPX"]),
        ("already_Slayed.exe", [".NET Reactor(6.x)[-]"]),
        ("a" * 57 + "_Slayed", [".NET Reactor(6.x)[-]"]),
    ],
)
def test_eziriz_deobfuscate_skip_guards(tmp_path, monkeypatch, filename, die_list):
    sample = tmp_path / filename
    sample.write_bytes(b"MZ-synthetic-sample")
    called = []
    monkeypatch.setattr(file_extra_info, "run_tool", lambda *a, **k: called.append((a, k)))

    res = file_extra_info.eziriz_deobfuscate(str(sample), data_dictionary={"die": die_list})
    assert res["result"] is None
    assert called == []


@pytest.mark.parametrize("conf_obj", [None, {}, {"binary": ""}, {"binary": "   "}, {"binary": None}])
def test_eziriz_deobfuscate_empty_or_missing_binary_config(tmp_path, monkeypatch, caplog, conf_obj):
    import logging

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ-synthetic-sample")
    called = []
    monkeypatch.setattr(file_extra_info, "tools_folder", str(tmp_path / "tools"))
    monkeypatch.setattr(file_extra_info.integration_conf, "eziriz_deobfuscate", conf_obj)
    monkeypatch.setattr(file_extra_info, "run_tool", lambda *a, **k: called.append((a, k)))

    with caplog.at_level(logging.WARNING, logger=file_extra_info.__name__):
        res = file_extra_info.eziriz_deobfuscate(str(sample), data_dictionary={"die": [".NET Reactor(6.x)[-]"]})

    assert res["result"] is None
    assert called == []
    assert any("eziriz_deobfuscate.binary is not defined" in r.message for r in caplog.records)


@pytest.mark.parametrize(
    ("filename", "conf_binary", "conf_extra_args", "expected_args_prefix", "slayed_out_name"),
    [
        (
            "sample.exe",
            "data/NETReactorSlayer.CLI",
            "",
            ["--no-pause", "True"],
            "sample_Slayed.exe",
        ),
        (
            "a" * 64,
            "/opt/tools/NETReactorSlayer.CLI",
            "--no-pause=False --dont-rename",
            ["--no-pause=False", "--dont-rename"],
            ("a" * 64) + "_Slayed",
        ),
    ],
)
def test_eziriz_deobfuscate_stages_isolated_workdir_and_moves_slayed(
    tmp_path,
    monkeypatch,
    filename,
    conf_binary,
    conf_extra_args,
    expected_args_prefix,
    slayed_out_name,
):
    import os
    import subprocess

    cuckoo_root = tmp_path / "cape"
    rel_tool = cuckoo_root / "data" / "NETReactorSlayer.CLI"
    rel_tool.parent.mkdir(parents=True)
    rel_tool.write_bytes(b"fake-tool")

    sample_dir = tmp_path / "binaries"
    sample_dir.mkdir()
    sample = sample_dir / filename
    sample.write_bytes(b"MZ-obfuscated-input")

    tools_dir = tmp_path / "tools"
    monkeypatch.setattr(file_extra_info, "CUCKOO_ROOT", str(cuckoo_root))
    monkeypatch.setattr(file_extra_info, "tools_folder", str(tools_dir))
    monkeypatch.setattr(
        file_extra_info.integration_conf,
        "eziriz_deobfuscate",
        {"binary": conf_binary, "extra_args": conf_extra_args},
    )

    expected_binary = os.path.join(str(cuckoo_root), conf_binary)
    orig_exists = os.path.exists
    orig_access = os.access
    monkeypatch.setattr(file_extra_info, "path_exists", lambda p: True if p == expected_binary else orig_exists(p))
    monkeypatch.setattr(os, "access", lambda p, mode: True if p == expected_binary else orig_access(p, mode))

    seen_calls = []

    def fake_run_tool(cmd, **kwargs):
        seen_calls.append((list(cmd), dict(kwargs)))
        staged = pathlib.Path(cmd[-1])
        assert staged.parent.name == "_work"
        assert staged.read_bytes() == b"MZ-obfuscated-input"
        (staged.parent / "PEImage.tmp").write_bytes(b"temp-image")
        (staged.parent / slayed_out_name).write_bytes(b"MZ-deobfuscated-output")
        return "Slayed\n"

    monkeypatch.setattr(file_extra_info, "run_tool", fake_run_tool)

    res = file_extra_info.eziriz_deobfuscate(str(sample), data_dictionary={"die": [".NET Reactor(6.9)[-]"]})
    result = res["result"]
    assert result is not None
    assert result["tool_name"] == "eziriz"
    assert result["extracted_files"] == [filename]

    assert len(seen_calls) == 1
    cmd, kwargs = seen_calls[0]
    assert cmd[0] == expected_binary
    assert cmd[1:-1] == expected_args_prefix
    assert cmd[-1].endswith(os.path.join("_work", filename))
    assert kwargs["universal_newlines"] is True
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.STDOUT

    tempdir = pathlib.Path(result["tempdir"])
    assert (tempdir / filename).read_bytes() == b"MZ-deobfuscated-output"
    assert not (tempdir / "_work").exists()
    assert list(sample_dir.iterdir()) == [sample]


def test_eziriz_deobfuscate_collects_dumped_assemblies_and_handles_backslashes(tmp_path, monkeypatch):
    sample = tmp_path / "sample.dll"
    sample.write_bytes(b"MZ-input-dll")
    tools_dir = tmp_path / "tools"
    fake_bin = tmp_path / "NETReactorSlayer.CLI"
    fake_bin.write_bytes(b"fake-tool")
    fake_bin.chmod(0o755)

    monkeypatch.setattr(file_extra_info, "tools_folder", str(tools_dir))
    monkeypatch.setattr(
        file_extra_info.integration_conf,
        "eziriz_deobfuscate",
        {"binary": str(fake_bin), "extra_args": ""},
    )

    def fake_run_tool(cmd, **kwargs):
        staged = pathlib.Path(cmd[-1])
        work_dir = staged.parent
        tempdir = work_dir.parent
        (work_dir / "PEImage.tmp").write_bytes(b"temp")
        (work_dir / "sample_Slayed.dll").write_bytes(b"MZ-slayed")
        (work_dir / "costura_lib.dll").write_bytes(b"MZ-costura")
        # Simulate Linux literal-backslash filenames created by String.Concat(SourceDir, "\\", name)
        (tempdir / "_work\\PEImage.tmp").write_bytes(b"stray-temp")
        (tempdir / "_work\\embedded.dll").write_bytes(b"MZ-embedded")
        (tempdir / "_work\\sample.dll").write_bytes(b"MZ-colliding-embedded")
        return "2 Embedded assemblies dumped\n"

    monkeypatch.setattr(file_extra_info, "run_tool", fake_run_tool)

    res = file_extra_info.eziriz_deobfuscate(str(sample), data_dictionary={"die": [".NET Reactor(6.8)[-]"]})
    result = res["result"]
    assert result is not None
    assert sorted(result["extracted_files"]) == [
        "costura_lib.dll",
        "embedded.dll",
        "sample (1).dll",
        "sample.dll",
    ]
    tempdir = pathlib.Path(result["tempdir"])
    assert (tempdir / "sample.dll").read_bytes() == b"MZ-slayed"
    assert (tempdir / "sample (1).dll").read_bytes() == b"MZ-colliding-embedded"
    assert (tempdir / "costura_lib.dll").read_bytes() == b"MZ-costura"
    assert (tempdir / "embedded.dll").read_bytes() == b"MZ-embedded"
    assert not (tempdir / "_work").exists()
    assert not any("\\" in p.name or "PEImage.tmp" in p.name for p in tempdir.iterdir())


@pytest.mark.parametrize("raise_exc", [False, True])
def test_eziriz_deobfuscate_empty_output_debug_log_and_error_cleanup(tmp_path, monkeypatch, caplog, raise_exc):
    import logging

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ-input")
    tools_dir = tmp_path / "tools"
    fake_bin = tmp_path / "NETReactorSlayer.CLI"
    fake_bin.write_bytes(b"fake-tool")
    fake_bin.chmod(0o755)

    monkeypatch.setattr(file_extra_info, "tools_folder", str(tools_dir))
    monkeypatch.setattr(
        file_extra_info.integration_conf,
        "eziriz_deobfuscate",
        {"binary": str(fake_bin), "extra_args": ""},
    )

    def fake_run_tool(cmd, **kwargs):
        staged = pathlib.Path(cmd[-1])
        (staged.parent / "PEImage.tmp").write_bytes(b"temp")
        if raise_exc:
            raise OSError("simulated execution failure")
        return "Unhandled error during deobfuscation\n"

    monkeypatch.setattr(file_extra_info, "run_tool", fake_run_tool)

    with caplog.at_level(logging.DEBUG, logger=file_extra_info.__name__):
        res = file_extra_info.eziriz_deobfuscate(str(sample), data_dictionary={"die": [".NET Reactor(6.9)[-]"]})

    result = res["result"]
    assert result is not None
    assert "extracted_files" not in result
    assert not (pathlib.Path(result["tempdir"]) / "_work").exists()
    if raise_exc:
        assert any("Exception was raised while attempting to use eziriz" in r.message for r in caplog.records)
    else:
        assert any("eziriz_deobfuscate produced no output files" in r.message for r in caplog.records)


def test_de4dot_deobfuscate_skips_non_mono(tmp_path, monkeypatch):
    sample = tmp_path / "native.exe"
    sample.write_bytes(b"MZ-native")
    called = []
    monkeypatch.setattr(file_extra_info, "run_tool", lambda *a, **k: called.append((a, k)))

    res = file_extra_info.de4dot_deobfuscate(str(sample), filetype="PE32 executable (GUI) Intel 80386, for MS Windows")
    assert res["result"] is None
    assert called == []


@pytest.mark.parametrize("conf_obj", [None, {}, {"binary": ""}, {"binary": "   "}, {"binary": None}])
def test_de4dot_deobfuscate_empty_or_missing_binary_config(tmp_path, monkeypatch, caplog, conf_obj):
    import logging

    sample = tmp_path / "dotnet.exe"
    sample.write_bytes(b"MZ-dotnet")
    called = []
    monkeypatch.setattr(file_extra_info, "tools_folder", str(tmp_path / "tools"))
    monkeypatch.setattr(file_extra_info.integration_conf, "de4dot_deobfuscate", conf_obj)
    monkeypatch.setattr(file_extra_info, "run_tool", lambda *a, **k: called.append((a, k)))

    with caplog.at_level(logging.WARNING, logger=file_extra_info.__name__):
        res = file_extra_info.de4dot_deobfuscate(str(sample), filetype="PE32 executable (GUI) Intel 80386 Mono/.Net assembly")

    assert res["result"] is None
    assert called == []
    assert any("de4dot_deobfuscate.binary is not defined" in r.message for r in caplog.records)


@pytest.mark.parametrize(
    ("conf_binary", "is_relative"),
    [
        ("data/de4dotEx/de4dot", True),
        ("/usr/local/bin/de4dot", False),
    ],
)
def test_de4dot_deobfuscate_paths_args_and_embedded_collection(tmp_path, monkeypatch, conf_binary, is_relative):
    import os
    import subprocess

    cuckoo_root = tmp_path / "cape"
    cuckoo_root.mkdir()
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ-mono")
    tools_dir = tmp_path / "tools"

    expected_binary = os.path.join(str(cuckoo_root), conf_binary) if is_relative else conf_binary
    orig_exists = os.path.exists
    orig_access = os.access
    monkeypatch.setattr(file_extra_info, "CUCKOO_ROOT", str(cuckoo_root))
    monkeypatch.setattr(file_extra_info, "tools_folder", str(tools_dir))
    monkeypatch.setattr(
        file_extra_info.integration_conf,
        "de4dot_deobfuscate",
        {"binary": conf_binary, "extra_args": "--dont-rename"},
    )
    monkeypatch.setattr(file_extra_info, "path_exists", lambda p: True if p == expected_binary else orig_exists(p))
    monkeypatch.setattr(os, "access", lambda p, mode: True if p == expected_binary else orig_access(p, mode))

    seen_calls = []

    def fake_run_tool(cmd, **kwargs):
        seen_calls.append((list(cmd), dict(kwargs)))
        out_path = pathlib.Path(cmd[cmd.index("-o") + 1])
        out_path.write_bytes(b"MZ-deobfuscated")
        (out_path.parent / "embedded.dll").write_bytes(b"MZ-embedded")
        return "Detected .NET Reactor >= 7.0\n"

    monkeypatch.setattr(file_extra_info, "run_tool", fake_run_tool)

    res = file_extra_info.de4dot_deobfuscate(
        str(sample),
        filetype="PE32 executable (GUI) Intel 80386 Mono/.Net assembly",
    )
    result = res["result"]
    assert result is not None
    assert result["tool_name"] == "de4dot"
    assert sorted(result["extracted_files"]) == ["embedded.dll", "sample.exe"]

    assert len(seen_calls) == 1
    cmd, kwargs = seen_calls[0]
    assert cmd[:-4] == [expected_binary, "--dont-rename"]
    assert cmd[-4:-1] == ["-f", str(sample), "-o"]
    assert kwargs["universal_newlines"] is True
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.STDOUT


def test_de4dot_deobfuscate_empty_output_debug_log(tmp_path, monkeypatch, caplog):
    import logging

    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ-mono")
    fake_bin = tmp_path / "de4dot"
    fake_bin.write_bytes(b"fake-bin")
    fake_bin.chmod(0o755)

    monkeypatch.setattr(file_extra_info, "tools_folder", str(tmp_path / "tools"))
    monkeypatch.setattr(
        file_extra_info.integration_conf,
        "de4dot_deobfuscate",
        {"binary": str(fake_bin), "extra_args": ""},
    )
    monkeypatch.setattr(file_extra_info, "run_tool", lambda *a, **k: "ERROR: failed to load\n")

    with caplog.at_level(logging.DEBUG, logger=file_extra_info.__name__):
        res = file_extra_info.de4dot_deobfuscate(
            str(sample),
            filetype="PE32 executable (GUI) Intel 80386 Mono/.Net assembly",
        )

    result = res["result"]
    assert result is not None
    assert "extracted_files" not in result
    assert any("de4dot_deobfuscate produced no output files" in r.message for r in caplog.records)


def test_integrations_default_conf_de4dotex_defaults():
    import configparser

    conf_path = pathlib.Path(__file__).resolve().parents[1] / "conf" / "default" / "integrations.conf.default"
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(conf_path, encoding="utf-8")

    assert parser.get("de4dot_deobfuscate", "enabled") == "yes"
    assert parser.get("de4dot_deobfuscate", "binary") == "/usr/local/bin/de4dot"
    assert parser.get("eziriz_deobfuscate", "enabled") == "no"
    assert parser.get("eziriz_deobfuscate", "binary") == ""

