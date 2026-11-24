"""Unit tests for the consolidated Windows Archive analysis package."""

import ctypes
import io
import json
import os
import tarfile
import zipfile
from unittest.mock import MagicMock

import pytest

if not hasattr(ctypes, "WINFUNCTYPE"):
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
if not hasattr(ctypes, "windll"):
    ctypes.windll = MagicMock()
    ctypes.windll.ntdll.NtQueryInformationProcess.return_value = 0
os.environ.setdefault("SystemDrive", "C:")
os.environ.setdefault("TMP", "/tmp")

from lib.common.constants import (
    OPT_APPDATA,
    OPT_CURDIR,
    OPT_EXTRACTOR,
    OPT_FILE,
    OPT_JSON_CONFIG,
    OPT_RECURSION_DEPTH,
)
from lib.common.exceptions import CuckooPackageError
from modules.packages import archive as archive_mod


def test_archive_stdlib_zip_and_tar_fallbacks(tmp_path, monkeypatch):
    monkeypatch.setattr(archive_mod, "upload_extracted_files", MagicMock())

    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("payload.exe", b"MZ\x90\x00")

    pkg = archive_mod.Archive(options={OPT_CURDIR: str(tmp_path / "zip_out")})
    pkg.get_path_app_in_path = MagicMock(side_effect=CuckooPackageError("missing"))
    pkg.execute_files = MagicMock(return_value=[1001])

    assert pkg.start(str(zip_path)) == [1001]
    assert (tmp_path / "zip_out" / "payload.exe").read_bytes() == b"MZ\x90\x00"

    tar_path = tmp_path / "sample.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tf:
        info = tarfile.TarInfo("drop.exe")
        data = b"MZ\x90\x00"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    pkg_tar = archive_mod.Archive(options={OPT_CURDIR: str(tmp_path / "tar_out")})
    pkg_tar.get_path_app_in_path = MagicMock(side_effect=CuckooPackageError("missing"))
    pkg_tar.execute_files = MagicMock(return_value=[1002])

    assert pkg_tar.start(str(tar_path)) == [1002]
    assert (tmp_path / "tar_out" / "drop.exe").read_bytes() == b"MZ\x90\x00"


def test_archive_explicit_extractor_pinning_disables_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(archive_mod, "upload_extracted_files", MagicMock())

    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("payload.exe", b"MZ\x90\x00")

    pkg = archive_mod.Archive(options={OPT_CURDIR: str(tmp_path / "out"), OPT_EXTRACTOR: "winrar"})
    pkg.get_path_app_in_path = MagicMock(side_effect=CuckooPackageError("Unable to find any WinRAR.exe executable"))
    with pytest.raises(CuckooPackageError, match="WinRAR.exe"):
        pkg.start(str(zip_path))

    pkg_bad = archive_mod.Archive(options={OPT_EXTRACTOR: "bogus"})
    with pytest.raises(CuckooPackageError, match="Unsupported extractor"):
        pkg_bad.start(str(zip_path))


def test_archive_compound_configuration_json_and_custom_json_config(tmp_path, monkeypatch):
    upload_mock = MagicMock()
    monkeypatch.setattr(archive_mod, "upload_extracted_files", upload_mock)

    dest_dir = tmp_path / "custom_dest"
    monkeypatch.setenv("CAPE_WIN_DEST", str(dest_dir))
    dest_ref = "%CAPE_WIN_DEST%" if archive_mod.os.name == "nt" else "$CAPE_WIN_DEST"

    zip_path = tmp_path / "compound.zip"
    cfg = {
        "path_to_extract": {"a.exe": dest_ref},
        "target_file": "a.exe",
    }
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("custom_manifest.json", json.dumps(cfg))
        zf.writestr("a.exe", b"MZ-COMPOUND")

    appdata = tmp_path / "appdata"
    appdata.mkdir()
    (appdata / "unrelated.exe").write_bytes(b"MZ-UNRELATED")
    monkeypatch.setenv("APPDATA", str(appdata))

    pkg = archive_mod.Archive(options={OPT_APPDATA: "yes", OPT_JSON_CONFIG: "custom_manifest.json"})
    pkg.get_path_app_in_path = MagicMock(side_effect=CuckooPackageError("missing"))
    seen = []
    pkg.execute_interesting_file = lambda root, name, path: seen.append((name, path)) or 2001

    assert pkg.start(str(zip_path)) == [2001]
    assert seen == [("a.exe", str(dest_dir / "a.exe"))]
    assert "unrelated.exe" not in upload_mock.call_args.args[1]


def test_archive_recursion_without_diec_and_file_override(tmp_path, monkeypatch):
    upload_mock = MagicMock()
    monkeypatch.setattr(archive_mod, "upload_extracted_files", upload_mock)

    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("nested.exe", b"MZ-NESTED")

    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())
        zf.writestr("other.exe", b"MZ-OTHER")

    pkg = archive_mod.Archive(
        options={OPT_CURDIR: str(tmp_path / "rec"), OPT_RECURSION_DEPTH: 1, OPT_FILE: "other.exe"}
    )
    pkg.get_path_app_in_path = MagicMock(side_effect=CuckooPackageError("missing"))
    seen = []
    pkg.execute_interesting_file = lambda root, name, path: seen.append(name) or 3001

    assert pkg.start(str(outer)) == [3001]
    assert seen == ["other.exe"]
    assert any(name.endswith("nested.exe") for name in upload_mock.call_args.args[1])
