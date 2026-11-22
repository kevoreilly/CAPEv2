import ctypes
import os
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

from lib.common.exceptions import CuckooPackageError
from modules.packages import nodejs


def _make_zip(path, entries):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


def test_setup_node_environment_extracts_nested_zip(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("USERPROFILE", str(profile))
    monkeypatch.setenv("PATH", "/existing/bin")

    _make_zip(
        tmp_path / "extras" / nodejs.NODE_ZIP_NAME,
        {
            "node-v25.2.1-win-x64/": b"",
            "node-v25.2.1-win-x64/other_node.exe": b"wrong",
            "node-v25.2.1-win-x64/node_modules/pkg/node.exe": b"nested",
            "node-v25.2.1-win-x64/node_modules/pkg/foo..bar.js": b"ok",
            "node-v25.2.1-win-x64/node.exe": b"real-node",
        },
    )

    node_exe, err = nodejs.setup_node_environment()

    expected = os.path.normpath(
        os.path.join(str(profile), "AppData", "Local", "app", nodejs.NODE_DIR_NAME, "node-v25.2.1-win-x64", "node.exe")
    )
    assert err is None
    assert node_exe == expected
    assert os.path.isfile(node_exe)
    with open(node_exe, "rb") as f:
        assert f.read() == b"real-node"
    assert os.environ["PATH"].split(os.pathsep)[0] == os.path.dirname(expected)


def test_setup_node_environment_extracts_root_zip_even_if_target_dir_exists(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    node_bin_dir = profile / "AppData" / "Local" / "app" / nodejs.NODE_DIR_NAME
    node_bin_dir.mkdir(parents=True)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("USERPROFILE", str(profile))
    monkeypatch.setenv("PATH", "")

    _make_zip(
        tmp_path / "extras" / nodejs.NODE_ZIP_NAME,
        {
            "node.exe": b"root-node",
            "npm.cmd": b"@echo off",
        },
    )

    node_exe, err = nodejs.setup_node_environment()

    expected = os.path.normpath(os.path.join(str(node_bin_dir), "node.exe"))
    assert err is None
    assert node_exe == expected
    assert os.path.isfile(node_exe)
    assert os.environ["PATH"] == os.path.dirname(expected)


def test_setup_node_environment_reuses_existing_extraction_and_dedupes_path(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("USERPROFILE", str(profile))
    monkeypatch.setenv("PATH", "/existing/bin")

    _make_zip(tmp_path / "extras" / nodejs.NODE_ZIP_NAME, {"node.exe": b"v1"})

    first_exe, first_err = nodejs.setup_node_environment()
    assert first_err is None
    assert first_exe is not None

    # Replace archive content; already-extracted binary should be reused without re-extracting.
    _make_zip(tmp_path / "extras" / nodejs.NODE_ZIP_NAME, {"node.exe": b"v2"})
    second_exe, second_err = nodejs.setup_node_environment()

    assert second_err is None
    assert second_exe == first_exe
    with open(second_exe, "rb") as f:
        assert f.read() == b"v1"
    path_parts = os.environ["PATH"].split(os.pathsep)
    assert path_parts.count(os.path.dirname(first_exe)) == 1


@pytest.mark.parametrize(
    "bad_member",
    [
        "../evil.exe",
        "node-v25/../../evil.exe",
        "/etc/evil.exe",
        "\\Windows\\evil.exe",
        "\\\\server\\share\\evil.exe",
        "C:\\evil.exe",
        "C:evil.exe",
        "../node.exe",
    ],
)
def test_setup_node_environment_rejects_path_traversal(tmp_path, monkeypatch, bad_member):
    profile = tmp_path / "profile"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("USERPROFILE", str(profile))

    entries = {"node.exe": b"ok", bad_member: b"evil"}
    if bad_member.endswith("node.exe"):
        entries = {bad_member: b"evil"}
    _make_zip(tmp_path / "extras" / nodejs.NODE_ZIP_NAME, entries)

    node_exe, err = nodejs.setup_node_environment()

    assert node_exe is None
    assert err is not None
    assert "malicious path" in err
    assert not (profile / "AppData" / "Local" / "app" / nodejs.NODE_DIR_NAME / "node.exe").exists()


def test_setup_node_environment_missing_or_invalid_zip(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("USERPROFILE", str(profile))

    # Missing zip
    node_exe, err = nodejs.setup_node_environment()
    assert node_exe is None
    assert "Zip not found" in err

    # Zip without exact node.exe (ignores suffix-only match and directory named node.exe/)
    _make_zip(
        tmp_path / "extras" / nodejs.NODE_ZIP_NAME,
        {"not_node.exe": b"nope", "node.exe/": b""},
    )
    node_exe, err = nodejs.setup_node_environment()
    assert node_exe is None
    assert err == "Archive does not contain node.exe"

    # Corrupt zip
    (tmp_path / "extras" / nodejs.NODE_ZIP_NAME).write_bytes(b"not a zip")
    node_exe, err = nodejs.setup_node_environment()
    assert node_exe is None
    assert "Exception during Node setup" in err


def test_nodejs_start_uses_custom_zip(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    sample = tmp_path / "sample.js"
    sample.write_text("console.log(1);")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("USERPROFILE", str(profile))
    monkeypatch.setenv("PATH", "")

    _make_zip(tmp_path / "extras" / nodejs.NODE_ZIP_NAME, {"node-v25/node.exe": b"node"})

    pkg = nodejs.NodeJS(options={"arguments": "--flag"})
    pkg.execute = MagicMock(return_value=1234)

    pid = pkg.start(str(sample))

    expected_bin = os.path.normpath(
        os.path.join(str(profile), "AppData", "Local", "app", nodejs.NODE_DIR_NAME, "node-v25", "node.exe")
    )
    assert pid == 1234
    pkg.execute.assert_called_once_with(expected_bin, f'"{sample}" --flag', str(sample))


def test_nodejs_start_falls_back_to_system_node_on_custom_failure(tmp_path, monkeypatch):
    sample = tmp_path / "sample.js"
    sample.write_text("console.log(1);")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "profile"))
    (tmp_path / "extras").mkdir()
    (tmp_path / "extras" / nodejs.NODE_ZIP_NAME).write_bytes(b"corrupt")

    pkg = nodejs.NodeJS(options={})
    pkg.get_path = MagicMock(return_value="C:\\Program Files\\nodejs\\node.exe")
    pkg.execute = MagicMock(return_value=4321)

    pid = pkg.start(str(sample))

    assert pid == 4321
    pkg.get_path.assert_called_once_with("node.exe")
    pkg.execute.assert_called_once_with("C:\\Program Files\\nodejs\\node.exe", f'"{sample}"', str(sample))


def test_nodejs_start_raises_cuckoo_package_error_if_no_binary(tmp_path, monkeypatch):
    sample = tmp_path / "sample.js"
    sample.write_text("console.log(1);")
    monkeypatch.chdir(tmp_path)

    pkg = nodejs.NodeJS(options={})
    pkg.get_path = MagicMock(return_value=None)

    with pytest.raises(CuckooPackageError):
        pkg.start(str(sample))
