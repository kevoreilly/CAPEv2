# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import tempfile
import unittest

import httpretty
import pytest

from lib.cuckoo.common.path_utils import path_delete, path_write_file
from lib.cuckoo.common.web_utils import (
    _download_file,
    download_file,
    force_int,
    get_file_content,
    parse_request_arguments,
)


@pytest.fixture
def paths():
    path_list = []
    for i in range(3):
        path_list += [tempfile.NamedTemporaryFile(delete=False).name]
        _ = path_write_file(path_list[i], str(i + 10), mode="text")
    yield path_list
    try:
        for i in path_list:
            path_delete(i)
    except Exception as e:
        print(("Error cleaning up, probably fine:" + str(e)))


@pytest.fixture
def path():
    onepath = tempfile.NamedTemporaryFile(delete=False)
    _ = path_write_file(onepath.name, "1338", mode="text")
    yield onepath.name
    try:
        path_delete(onepath.name)
    except Exception as e:
        print(("Error cleaning up, probably fine:" + str(e)))


def test_get_file_content(paths):
    assert get_file_content(paths) == b"10"


def test_get_file_contents_path(path):
    assert get_file_content(path) == b"1338"


@httpretty.activate
def test__download_file():
    httpretty.register_uri(httpretty.GET, "http://mordor.eye/onering", body="frodo")
    assert _download_file(route=None, url="http://mordor.eye/onering", options="dne_abc=123,dne_def=456") == b"frodo"


@pytest.fixture
def mock_request():
    class MockReq:
        POST = {"clock": "03-31-2021 14:24:36"}

    yield MockReq()


def test_parse_request_arguments(mock_request):
    ret = parse_request_arguments(mock_request)

    assert ret == (
        "",
        "",
        0,
        0,
        "",
        "",
        "",
        None,
        "",
        False,
        "03-31-2021 14:24:36",
        False,
        False,
        None,
        None,
        None,
        "",
        "",
    )


def test_force_int():
    assert force_int(value="1") == 1
    assert force_int(value="$") == 0


class SubmissionRequest:
    def __init__(self, *, machine="", platform=""):
        self.POST = {
            "machine": machine,
            "platform": platform,
        }
        self.FILES = [object()]


@pytest.mark.parametrize(
    "archive_name,magic_type",
    (
        ("sample.zip", "Zip archive data, at least v2.0 to extract"),
        ("sample.tar", "POSIX tar archive"),
        ("sample.gz", "gzip compressed data, was"),
    ),
)
def test_archive_reaches_demux_without_inferred_platform(
    tmp_path,
    monkeypatch,
    archive_name,
    magic_type,
):
    """A container must not be assigned a platform before its contents are inspected."""
    archive = tmp_path / archive_name
    archive.write_bytes(b"harmless test container")

    request = SubmissionRequest()
    observed = {}

    class FakeDatabase:
        def identify_submission_package(self, *_args, **_kwargs):
            return "", "container", True

        def demux_sample_and_add_to_db(self, **kwargs):
            observed.update(kwargs)
            return [101], {}

    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.DYNAMIC_PLATFORM_DETERMINATION",
        True,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.get_magic_type",
        lambda _path: magic_type,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.load_vms_exits",
        lambda: {},
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.save_script_to_storage",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.db",
        FakeDatabase(),
    )

    status, result = download_file(
        request=request,
        content=archive.read_bytes(),
        path=str(archive),
        service="regression-test",
        options="",
        task_ids=[],
        errors=[],
        url=False,
        fhash=False,
    )

    assert status == "ok"
    assert result["task_ids"] == [101]
    assert observed["platform"] == ""


@pytest.mark.parametrize(
    "archive_name,magic_type",
    (
        ("linux-payload.zip", "Zip archive data, at least v2.0 to extract"),
        ("linux-payload.tar", "POSIX tar archive"),
        ("linux-payload.gz", "gzip compressed data, was"),
    ),
)
def test_archive_with_linux_machine_is_not_rejected_before_demux(
    tmp_path,
    monkeypatch,
    archive_name,
    magic_type,
):
    """A container must reach demux before machine compatibility is evaluated."""
    archive = tmp_path / archive_name
    archive.write_bytes(b"harmless test container")

    request = SubmissionRequest(machine="linux-vm")
    observed = {}

    class LinuxMachine:
        platform = "linux"

    class FakeDatabase:
        def identify_submission_package(self, *_args, **_kwargs):
            return "", "container", True

        def view_machine(self, machine):
            assert machine == "linux-vm"
            return LinuxMachine()

        def demux_sample_and_add_to_db(self, **kwargs):
            observed.update(kwargs)
            return [102], {}

    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.DYNAMIC_PLATFORM_DETERMINATION",
        True,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.get_magic_type",
        lambda _path: magic_type,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.load_vms_exits",
        lambda: {},
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.save_script_to_storage",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.db",
        FakeDatabase(),
    )

    status, result = download_file(
        request=request,
        content=archive.read_bytes(),
        path=str(archive),
        service="regression-test",
        options="",
        task_ids=[],
        errors=[],
        url=False,
        fhash=False,
    )

    assert status == "ok"
    assert result["task_ids"] == [102]
    assert observed["machine"] == "linux-vm"
    assert observed["platform"] == ""


@pytest.mark.parametrize(
    "magic_type,detected_platform",
    (
        ("PE32 executable, for MS Windows", "windows"),
        ("ELF 64-bit LSB executable", "linux"),
    ),
)
def test_direct_executable_reaches_demux_with_inferred_platform(
    tmp_path,
    monkeypatch,
    magic_type,
    detected_platform,
):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"harmless executable fixture")

    request = SubmissionRequest()
    observed = {}

    class FakeFile:
        def __init__(self, _path):
            pass

        def get_platform(self):
            return detected_platform

    class FakeDatabase:
        def identify_submission_package(self, *_args, **_kwargs):
            return "", detected_platform, False

        def demux_sample_and_add_to_db(self, **kwargs):
            observed.update(kwargs)
            return [103], {}

    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.DYNAMIC_PLATFORM_DETERMINATION",
        True,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.linux_enabled",
        True,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.File",
        FakeFile,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.get_magic_type",
        lambda _path: magic_type,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.load_vms_exits",
        lambda: {},
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.save_script_to_storage",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.db",
        FakeDatabase(),
    )

    status, result = download_file(
        request=request,
        content=sample.read_bytes(),
        path=str(sample),
        service="regression-test",
        options="",
        task_ids=[],
        errors=[],
        url=False,
        fhash=False,
    )

    assert status == "ok"
    assert result["task_ids"] == [103]
    assert observed["platform"] == detected_platform


def test_generic_demux_preserves_machine_all_until_platform_is_known(
    tmp_path,
    monkeypatch,
):
    archive = tmp_path / "payload.container"
    archive.write_bytes(b"harmless test container")

    request = SubmissionRequest(machine="all")
    observed = {}

    class FakeDatabase:
        def identify_submission_package(self, *_args, **_kwargs):
            return "", "container", True

        def list_machines(self, **_kwargs):
            raise AssertionError(
                "Machines must not be expanded before generic demux"
            )

        def demux_sample_and_add_to_db(self, **kwargs):
            observed.update(kwargs)
            return [104], {}

    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.DYNAMIC_PLATFORM_DETERMINATION",
        True,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.get_magic_type",
        lambda _path: "generic container",
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.load_vms_exits",
        lambda: {},
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.save_script_to_storage",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "lib.cuckoo.common.web_utils.db",
        FakeDatabase(),
    )

    status, result = download_file(
        request=request,
        content=archive.read_bytes(),
        path=str(archive),
        service="regression-test",
        options="",
        task_ids=[],
        errors=[],
        url=False,
        fhash=False,
    )

    assert status == "ok"
    assert result["task_ids"] == [104]
    assert observed["machine"] == "all"
    assert observed["platform"] == ""


if __name__ == "__main__":
    unittest.main()
