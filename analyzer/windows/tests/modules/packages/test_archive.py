"""Unit tests for the consolidated Windows Archive analysis package."""

import ctypes
import gzip
import io
import json
import os
import sys
import tarfile
import types
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


def test_archive_file_option_resolves_nested_single_member_and_extensionless_tar(tmp_path, monkeypatch):
    upload_mock = MagicMock()
    monkeypatch.setattr(archive_mod, "upload_extracted_files", upload_mock)

    # 1. Single-member nested ZIP with OPT_FILE targeting inner member
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("sub/payload.exe", b"MZ-INNER")

    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner.getvalue())

    pkg = archive_mod.Archive(options={OPT_CURDIR: str(tmp_path / "nested_out"), OPT_FILE: "sub/payload.exe"})
    pkg.get_path_app_in_path = MagicMock(side_effect=CuckooPackageError("missing"))
    seen = []
    pkg.execute_interesting_file = lambda root, name, path: seen.append((name, path)) or 4001

    assert pkg.start(str(outer)) == [4001]
    assert len(seen) == 1
    assert seen[0][0].replace("\\", "/").endswith("sub/payload.exe")
    assert os.path.isfile(seen[0][1])

    # 2. Extensionless tar extracted by 7z from a .gz stream is unwrapped via magic detection
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        info = tarfile.TarInfo("drop.exe")
        data = b"MZ-TAR"
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    gz_path = tmp_path / "archive.gz"
    with gzip.open(gz_path, "wb") as gf:
        gf.write(tar_buf.getvalue())

    def fake_7z_extract(_bin, src, dest, _pw, _multi):
        if src == str(gz_path):
            with open(os.path.join(dest, "archive"), "wb") as f:
                f.write(tar_buf.getvalue())
        else:
            with open(os.path.join(dest, "drop.exe"), "wb") as f:
                f.write(b"MZ-TAR")

    monkeypatch.setattr(archive_mod, "extract_archive", fake_7z_extract)
    pkg_gz = archive_mod.Archive(options={OPT_CURDIR: str(tmp_path / "gz_out"), OPT_FILE: "drop.exe"})
    pkg_gz.get_path_app_in_path = MagicMock(side_effect=lambda app: "C:\\7z.exe" if app == "7z.exe" else (_ for _ in ()).throw(CuckooPackageError("missing")))
    seen_gz = []
    pkg_gz.execute_interesting_file = lambda root, name, path: seen_gz.append((name, path)) or 4002

    assert pkg_gz.start(str(gz_path)) == [4002]
    assert len(seen_gz) == 1
    assert seen_gz[0][0].replace("\\", "/").endswith("drop.exe")
    assert os.path.isfile(seen_gz[0][1])

    # 3. Traversal OPT_FILE is rejected instead of resolved
    pkg_trav = archive_mod.Archive(options={OPT_CURDIR: str(tmp_path / "trav_out"), OPT_FILE: "../escape.exe"})
    pkg_trav.get_path_app_in_path = MagicMock(side_effect=CuckooPackageError("missing"))
    with pytest.raises(CuckooPackageError, match="outside the extraction directory"):
        pkg_trav.start(str(outer))


def test_archive_compound_self_move_pruned_moves_and_manifest_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(archive_mod, "upload_extracted_files", MagicMock())

    # 1. Self-move (root == APPDATA and path_to_extract targets %APPDATA%) must not delete folder_b
    appdata = tmp_path / "appdata_self"
    appdata.mkdir()
    monkeypatch.setenv("APPDATA", str(appdata))
    appdata_ref = "%APPDATA%" if archive_mod.os.name == "nt" else "$APPDATA"

    self_zip = tmp_path / "self_move.zip"
    cfg_self = {
        "path_to_extract": {"folder_b": appdata_ref, "a.exe": appdata_ref},
        "target_file": "a.exe",
    }
    with zipfile.ZipFile(self_zip, "w") as zf:
        zf.writestr("__configuration.json", json.dumps(cfg_self))
        zf.writestr("a.exe", b"MZ-SELF")
        zf.writestr("folder_b/dep.dll", b"MZ-DEP")

    pkg_self = archive_mod.Archive(options={OPT_APPDATA: "yes"})
    pkg_self.get_path_app_in_path = MagicMock(side_effect=CuckooPackageError("missing"))
    seen = []
    pkg_self.execute_interesting_file = lambda root, name, path: seen.append((name, path)) or 5001

    assert pkg_self.start(str(self_zip)) == [5001]
    assert (appdata / "folder_b" / "dep.dll").read_bytes() == b"MZ-DEP"
    assert seen == [("a.exe", str(appdata / "a.exe"))]

    # 2. Moved entries without target_file are pruned from auto-execution candidates
    moved_dir = tmp_path / "moved_helpers"
    monkeypatch.setenv("CAPE_MOVED_HELPERS", str(moved_dir))
    moved_ref = "%CAPE_MOVED_HELPERS%" if archive_mod.os.name == "nt" else "$CAPE_MOVED_HELPERS"

    prune_zip = tmp_path / "prune.zip"
    with zipfile.ZipFile(prune_zip, "w") as zf:
        zf.writestr("__configuration.json", json.dumps({"path_to_extract": {"helper.dll": moved_ref}}))
        zf.writestr("helper.dll", b"MZ-HELPER")
        zf.writestr("run.exe", b"MZ-RUN")

    pkg_prune = archive_mod.Archive(options={OPT_CURDIR: str(tmp_path / "prune_root")})
    pkg_prune.get_path_app_in_path = MagicMock(side_effect=CuckooPackageError("missing"))
    ran = []
    pkg_prune.execute_interesting_file = lambda root, name, path: ran.append(name) or 5002

    assert pkg_prune.start(str(prune_zip)) == [5002]
    assert ran == ["run.exe"]
    assert (moved_dir / "helper.dll").read_bytes() == b"MZ-HELPER"

    # 3. Traversal json_config is rejected even when target does not exist
    pkg_bad_cfg = archive_mod.Archive(
        options={OPT_CURDIR: str(tmp_path / "bad_cfg_root"), OPT_JSON_CONFIG: "../nonexistent.json"}
    )
    pkg_bad_cfg.get_path_app_in_path = MagicMock(side_effect=CuckooPackageError("missing"))
    with pytest.raises(CuckooPackageError, match="outside the extraction directory"):
        pkg_bad_cfg.start(str(prune_zip))

    # 4. Non-dict JSON manifest raises CuckooPackageError
    list_zip = tmp_path / "list_manifest.zip"
    with zipfile.ZipFile(list_zip, "w") as zf:
        zf.writestr("__configuration.json", '["not", "an", "object"]')
        zf.writestr("run.exe", b"MZ")

    pkg_list = archive_mod.Archive(options={OPT_CURDIR: str(tmp_path / "list_root")})
    pkg_list.get_path_app_in_path = MagicMock(side_effect=CuckooPackageError("missing"))
    with pytest.raises(CuckooPackageError, match="expected JSON object"):
        pkg_list.start(str(list_zip))


def test_zip_utils_winrar_rarfile_and_zip_edge_cases(tmp_path, monkeypatch):
    from lib.common import zip_utils

    # 1. extract_zip does not rename source archive when extracting to a different directory
    src_dir = tmp_path / "src"
    out_dir = tmp_path / "out"
    src_dir.mkdir()
    same_zip = src_dir / "sample.zip"
    with zipfile.ZipFile(same_zip, "w") as zf:
        zf.writestr("sample.zip", b"nested-bytes")

    zip_utils.extract_zip(str(same_zip), str(out_dir), recursive=False)
    assert same_zip.exists()
    assert not (src_dir / "sample.zip.old").exists()
    assert (out_dir / "sample.zip").read_bytes() == b"nested-bytes"

    # 2. extract_zip wraps OSError from conflicting file/directory member names as CuckooPackageError
    conflict_zip = tmp_path / "conflict.zip"
    with zipfile.ZipFile(conflict_zip, "w") as zf:
        zf.writestr("a", b"file-a")
        zf.writestr("a/b", b"file-b")
    with pytest.raises(CuckooPackageError, match="Unable to extract Zip file"):
        zip_utils.extract_zip(str(conflict_zip), str(tmp_path / "conflict_out"), recursive=False)

    # 3. winrar_extractor checks wrong password BEFORE partial entries and appends trailing os.sep
    winrar_out = tmp_path / "winrar_out"
    seen_cmds = []

    def fake_winrar_run(cmd, **kwargs):
        seen_cmds.append(cmd)
        if "-pbad" in cmd:
            (winrar_out / "empty_subdir").mkdir(exist_ok=True)
            return MagicMock(returncode=11, stdout=b"", stderr=b"Wrong password")
        (winrar_out / "ok.exe").write_bytes(b"MZ-OK")
        return MagicMock(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(zip_utils.subprocess, "run", fake_winrar_run)
    extracted = zip_utils.winrar_extractor(
        "C:\\WinRAR.exe", str(winrar_out), str(tmp_path / "enc.rar"), "bad:good", try_multiple_passwords=True
    )
    assert seen_cmds[0][-1].endswith(os.sep)
    assert "ok.exe" in extracted
    assert not (winrar_out / "empty_subdir").exists()

    winrar_fail_out = tmp_path / "winrar_fail_out"

    def fake_winrar_always_wrong(cmd, **kwargs):
        (winrar_fail_out / "partial_dir").mkdir(exist_ok=True)
        return MagicMock(returncode=11, stdout=b"", stderr=b"")

    monkeypatch.setattr(zip_utils.subprocess, "run", fake_winrar_always_wrong)
    with pytest.raises(CuckooPackageError, match="Wrong password"):
        zip_utils.winrar_extractor("C:\\WinRAR.exe", str(winrar_fail_out), str(tmp_path / "enc.rar"), "bad")
    assert list(winrar_fail_out.iterdir()) == []

    # 4. extract_rar_with_rarfile calls setpassword() for header-encrypted (-hp) RARs
    fake_rarfile = types.ModuleType("rarfile")

    class FakeBadRarFile(Exception):
        pass

    class FakeWrongPassword(Exception):
        pass

    class FakePasswordRequired(Exception):
        pass

    class FakeInfo:
        def __init__(self, filename):
            self.filename = filename

        def is_symlink(self):
            return False

        def is_dir(self):
            return False

    class FakeHeaderEncryptedRar:
        def __init__(self, path, mode="r"):
            self._pw = None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def needs_password(self):
            return True

        def setpassword(self, pwd):
            self._pw = pwd

        def infolist(self):
            if self._pw == "secret":
                return [FakeInfo("hp_payload.exe")]
            return []

        def open(self, info, mode="r", pwd=None):
            if self._pw != "secret":
                raise FakeWrongPassword("wrong")
            return io.BytesIO(b"MZ-HP")

    fake_rarfile.BadRarFile = FakeBadRarFile
    fake_rarfile.RarWrongPassword = FakeWrongPassword
    fake_rarfile.PasswordRequired = FakePasswordRequired
    fake_rarfile.RarFile = FakeHeaderEncryptedRar
    monkeypatch.setitem(sys.modules, "rarfile", fake_rarfile)

    rar_out = tmp_path / "rar_hp_out"
    zip_utils.extract_rar_with_rarfile(
        str(tmp_path / "hp.rar"), str(rar_out), password="wrong:secret", try_multiple_passwords=True
    )
    assert (rar_out / "hp_payload.exe").read_bytes() == b"MZ-HP"

    with pytest.raises(CuckooPackageError, match="Wrong password"):
        zip_utils.extract_rar_with_rarfile(str(tmp_path / "hp.rar"), str(tmp_path / "rar_hp_bad"), password="wrong")


def test_execute_interesting_file_handles_cross_drive_commonpath_valueerror(tmp_path, monkeypatch):
    from lib.common import abstracts

    root_dir = tmp_path / "root"
    cur_dir = tmp_path / "other_drive"
    root_dir.mkdir()
    cur_dir.mkdir()
    sample = cur_dir / "script.bat"
    sample.write_text("@echo off\n")

    real_commonpath = os.path.commonpath
    real_root = os.path.realpath(str(root_dir))

    def fake_commonpath(paths):
        if paths[0] == real_root:
            raise ValueError("Paths don't have the same drive")
        return real_commonpath(paths)

    monkeypatch.setattr(abstracts.os.path, "commonpath", fake_commonpath)
    pkg = archive_mod.Archive(options={OPT_CURDIR: str(cur_dir)})
    pkg.get_path = MagicMock(return_value="C:\\Windows\\System32\\cmd.exe")
    pkg.execute = MagicMock(return_value=9001)

    assert pkg.execute_interesting_file(str(root_dir), "script.bat", str(sample)) == 9001


def test_execute_files_free_mode_does_not_count_skipped_non_executables(tmp_path, monkeypatch):
    from lib.common.constants import OPT_FREE

    pkg = archive_mod.Archive(options={OPT_FREE: True})
    launched = []

    def fake_super_execute(path, args, interest):
        launched.append(os.path.basename(path))
        return None

    monkeypatch.setattr(archive_mod.Package, "execute", lambda self, path, args, interest: fake_super_execute(path, args, interest))

    def fake_exec_interesting(root, name, path):
        if name.endswith(".exe"):
            return pkg.execute(path, "", path)
        return None

    pkg.execute_interesting_file = fake_exec_interesting
    files = ["first.exe", "blob1.dat", "blob2.db", "blob3.tmp", "second.exe", "third.exe"]
    assert pkg.execute_files(str(tmp_path), files, max_executables=2) == []
    assert launched == ["first.exe", "second.exe"]


def test_archive_recursion_skips_symlinks(tmp_path, monkeypatch):
    outside_zip = tmp_path / "outside.zip"
    with zipfile.ZipFile(outside_zip, "w") as zf:
        zf.writestr("secret.exe", b"MZ-SECRET")

    sample_zip = tmp_path / "sample.zip"
    sample_zip.write_bytes(b"PK\x03\x04")
    out_dir = tmp_path / "out"

    monkeypatch.setattr(archive_mod, "upload_extracted_files", MagicMock())
    extracted_sources = []

    def fake_extract(_bin, src, dest, _pw, _multi):
        extracted_sources.append(src)
        with open(os.path.join(dest, "ok.exe"), "wb") as f:
            f.write(b"MZ-OK")
        try:
            os.symlink(str(outside_zip), os.path.join(dest, "escape.zip"))
        except OSError:
            pytest.skip("Symlink creation requires elevated privileges on this platform")

    monkeypatch.setattr(archive_mod, "extract_archive", fake_extract)
    pkg = archive_mod.Archive(options={OPT_CURDIR: str(out_dir), OPT_RECURSION_DEPTH: 1})
    pkg.get_path_app_in_path = MagicMock(
        side_effect=lambda app: "C:\\7z.exe" if app == "7z.exe" else (_ for _ in ()).throw(CuckooPackageError("missing"))
    )
    pkg.execute_files = MagicMock(return_value=[7001])

    assert pkg.start(str(sample_zip)) == [7001]
    assert extracted_sources == [str(sample_zip)]
