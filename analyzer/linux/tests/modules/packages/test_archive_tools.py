import io
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock
from zipfile import ZipFile

import pytest

from lib.common import abstracts
from modules.packages import archive


@pytest.fixture
def seven_zip():
    binary = shutil.which("7z") or shutil.which("7zz")
    if binary is None:
        pytest.skip("7-Zip is required for real archive extraction")
    return binary


@pytest.fixture
def real_archive_package(monkeypatch, tmp_path, seven_zip):
    monkeypatch.setenv("TEMP", str(tmp_path))
    monkeypatch.setattr(abstracts, "NetlogFile", Mock)
    monkeypatch.setattr(archive, "upload_extracted_files", lambda *args: None)
    packages = []

    def make(options=None):
        package = archive.Archive(options=options or {})
        package.get_path_app_in_path = lambda application: shutil.which("file") if application == "file" else seven_zip
        outputs = []

        def execute(command):
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = process.communicate(timeout=5)
                assert process.returncode == 0, stderr
                outputs.append(stdout)
                return process.pid
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

        package.execute = execute
        packages.append(package)
        return package, outputs

    yield make
    for package in packages:
        package.finish()


def test_recursive_output_does_not_collide_with_members(real_archive_package, tmp_path):
    if shutil.which("file") is None:
        pytest.skip("file is required for recursive archive extraction")
    nested = io.BytesIO()
    with ZipFile(nested, "w") as bundle:
        bundle.writestr("payload.sh", "printf nested-ok")
    target = tmp_path / "sample.zip"
    with ZipFile(target, "w") as bundle:
        bundle.writestr("0", "documentation")
        bundle.writestr("inner.zip", nested.getvalue())
    package, outputs = real_archive_package({"recursion_depth": 1})
    pids = package.start(str(target))
    assert len(pids) == 1 and isinstance(pids[0], int)
    assert outputs == [b"nested-ok"]
    root = Path(package._extraction_dir.name)
    assert (root / "0").read_text() == "documentation"
    children = list(root.glob("nested-*/payload.sh"))
    assert len(children) == 1
    assert children[0].read_text() == "printf nested-ok"
    package.finish()
    assert not root.exists()
