import pytest
import os
import hashlib
import tempfile

# Ideally, this function would be imported from your application code
def check_completion_logic(config):
    complete_folder = hashlib.md5(f"cape-{config.id}".encode()).hexdigest()
    complete_analysis_patterns = [os.path.join(os.environ["TMP"], complete_folder)]
    if "SystemRoot" in os.environ:
        complete_analysis_patterns.append(os.path.join(os.environ["SystemRoot"], "Temp", complete_folder))

    return any(os.path.isdir(path) for path in complete_analysis_patterns)

class MockConfig:
    id = 123

@pytest.fixture
def mock_env(monkeypatch):
    """Pytest fixture to mock environment and create temp dirs."""
    with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as sysroot_dir:
        monkeypatch.setenv("TMP", tmp_dir)
        monkeypatch.setenv("SystemRoot", sysroot_dir)
        os.makedirs(os.path.join(sysroot_dir, "Temp"), exist_ok=True)
        yield

def test_completion_folder_in_tmp(mock_env):
    config = MockConfig()
    complete_folder = hashlib.md5(f"cape-{config.id}".encode()).hexdigest()
    path = os.path.join(os.environ["TMP"], complete_folder)
    os.makedirs(path)

    assert check_completion_logic(config) is True

    os.rmdir(path)
    assert check_completion_logic(config) is False

def test_completion_folder_in_systemroot(mock_env):
    config = MockConfig()
    complete_folder = hashlib.md5(f"cape-{config.id}".encode()).hexdigest()
    path = os.path.join(os.environ["SystemRoot"], "Temp", complete_folder)
    os.makedirs(path)

    assert check_completion_logic(config) is True

    os.rmdir(path)
    assert check_completion_logic(config) is False


def test_error_elevation_required():
    from analyzer.windows.lib.common.errors import get_error_string

    err_740 = get_error_string(740)
    assert "ERROR_ELEVATION_REQUIRED" in err_740
    assert "elevation" in err_740.lower()

    err_1223 = get_error_string(1223)
    assert "ERROR_CANCELLED" in err_1223


def test_archive_multi_file_partial_failure(monkeypatch):
    from unittest.mock import MagicMock
    from analyzer.windows.lib.common.exceptions import CuckooPackageError
    from analyzer.windows.modules.packages.archive import Archive

    archive_pkg = Archive(options={}, config=MagicMock())

    monkeypatch.setattr(
        "analyzer.windows.modules.packages.archive.get_interesting_files",
        lambda file_names: ["failing.exe", "working.exe"],
    )

    def mock_execute(root, name, path):
        if name == "failing.exe":
            raise CuckooPackageError("elevation required")
        return [1234]

    archive_pkg.execute_interesting_file = mock_execute

    monkeypatch.setattr(
        os, "walk", lambda folder: [("C:\\extracted", [], ["failing.exe", "working.exe"])]
    )

    pids = archive_pkg.start("dummy_target.zip")
    assert pids == [1234]


def test_archive_all_files_fail(monkeypatch):
    from unittest.mock import MagicMock
    from analyzer.windows.lib.common.exceptions import CuckooPackageError
    from analyzer.windows.modules.packages.archive import Archive

    archive_pkg = Archive(options={}, config=MagicMock())

    monkeypatch.setattr(
        "analyzer.windows.modules.packages.archive.get_interesting_files",
        lambda file_names: ["failing1.exe", "failing2.exe"],
    )

    def mock_execute(root, name, path):
        raise CuckooPackageError("failed execution")

    archive_pkg.execute_interesting_file = mock_execute

    monkeypatch.setattr(
        os, "walk", lambda folder: [("C:\\extracted", [], ["failing1.exe", "failing2.exe"])]
    )

    with pytest.raises(CuckooPackageError, match="failed execution"):
        archive_pkg.start("dummy_target.zip")
