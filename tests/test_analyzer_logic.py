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


@pytest.fixture
def mock_archive_package(monkeypatch):
    import importlib.util
    import sys
    import types
    from unittest.mock import MagicMock

    mock_lib_common = types.ModuleType("lib.common")
    monkeypatch.setitem(sys.modules, "lib.common", mock_lib_common)

    mock_constants = types.ModuleType("lib.common.constants")
    for opt in [
        "OPT_ARGUMENTS",
        "OPT_DLLLOADER",
        "OPT_FILE",
        "OPT_FUNCTION",
        "OPT_MULTI_PASSWORD",
        "OPT_PASSWORD",
        "OPT_RECURSION_DEPTH",
    ]:
        setattr(mock_constants, opt, opt)
    mock_constants.ARCHIVE_OPTIONS = (
        mock_constants.OPT_FILE,
        mock_constants.OPT_PASSWORD,
        mock_constants.OPT_RECURSION_DEPTH,
    )
    mock_constants.DLL_OPTIONS = (
        mock_constants.OPT_ARGUMENTS,
        mock_constants.OPT_DLLLOADER,
        mock_constants.OPT_FUNCTION,
    )
    monkeypatch.setitem(sys.modules, "lib.common.constants", mock_constants)

    mock_exceptions = types.ModuleType("lib.common.exceptions")

    class CuckooPackageError(Exception):
        pass

    mock_exceptions.CuckooPackageError = CuckooPackageError
    monkeypatch.setitem(sys.modules, "lib.common.exceptions", mock_exceptions)

    mock_abstracts = types.ModuleType("lib.common.abstracts")

    class MockPackage:
        def __init__(self, options=None, config=None):
            self.options = options or {}
            self.config = config

    mock_abstracts.Package = MockPackage
    monkeypatch.setitem(sys.modules, "lib.common.abstracts", mock_abstracts)

    mock_zip_utils = types.ModuleType("lib.common.zip_utils")
    mock_zip_utils.attempt_multiple_passwords = MagicMock()
    mock_zip_utils.extract_archive = MagicMock()
    mock_zip_utils.get_file_names = lambda path, pswd: []
    mock_zip_utils.get_interesting_files = lambda files: files
    mock_zip_utils.upload_extracted_files = MagicMock()
    mock_zip_utils.winrar_extractor = MagicMock()
    monkeypatch.setitem(sys.modules, "lib.common.zip_utils", mock_zip_utils)

    mock_modules_packages = types.ModuleType("modules.packages")
    mock_modules_packages_dll = types.ModuleType("modules.packages.dll")
    mock_modules_packages_dll.DLL_OPTIONS = mock_constants.DLL_OPTIONS
    monkeypatch.setitem(sys.modules, "modules.packages", mock_modules_packages)
    monkeypatch.setitem(sys.modules, "modules.packages.dll", mock_modules_packages_dll)

    spec = importlib.util.spec_from_file_location(
        "archive",
        os.path.join(os.path.dirname(__file__), "../analyzer/windows/modules/packages/archive.py"),
    )
    archive_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive_mod)
    return archive_mod.Archive, CuckooPackageError


def test_archive_multi_file_partial_failure(mock_archive_package):
    Archive, CuckooPackageError = mock_archive_package
    from unittest.mock import MagicMock

    archive_pkg = Archive(options={}, config=MagicMock())

    def mock_execute(root, name, path):
        if name == "failing.exe":
            raise CuckooPackageError("elevation required")
        return [1234]

    archive_pkg.execute_interesting_file = mock_execute
    pids = archive_pkg.execute_files("C:\\extracted", ["failing.exe", "working.exe"])
    assert pids == [1234]


def test_archive_all_files_fail(mock_archive_package):
    Archive, CuckooPackageError = mock_archive_package
    from unittest.mock import MagicMock

    archive_pkg = Archive(options={}, config=MagicMock())

    def mock_execute(root, name, path):
        raise CuckooPackageError("failed execution")

    archive_pkg.execute_interesting_file = mock_execute

    with pytest.raises(CuckooPackageError, match="failed execution"):
        archive_pkg.execute_files("C:\\extracted", ["failing1.exe", "failing2.exe"])
