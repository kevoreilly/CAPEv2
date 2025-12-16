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
