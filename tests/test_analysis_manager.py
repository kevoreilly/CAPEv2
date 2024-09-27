import datetime
import logging
import os
import pathlib
from typing import Generator

import pytest
from pytest_mock import MockerFixture

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import ConfigMeta
from lib.cuckoo.core.analysis_manager import AnalysisManager
from lib.cuckoo.core.database import TASK_RUNNING, Guest, Machine, Task, _Database
from lib.cuckoo.core.machinery_manager import MachineryManager
from lib.cuckoo.core.scheduler import Scheduler


class MockMachinery(Machinery):
    module_name = "mock"

    def read_config(self):
        return {
            "mock": {
                "machines": "name0",
            },
            "name0": {
                "label": "label0",
                "platform": "windows",
                "arch": "x64",
                "ip": "1.2.3.4",
            },
        }

    def _list(self):
        return ["name0"]


@pytest.fixture
def machinery() -> Generator[MockMachinery, None, None]:
    yield MockMachinery()


@pytest.mark.usefixtures("db")
@pytest.fixture
def machinery_manager(
    custom_conf_path: pathlib.Path, monkeypatch, machinery: MockMachinery
) -> Generator[MachineryManager, None, None]:
    confd_path = custom_conf_path / "cuckoo.conf.d"
    confd_path.mkdir(0o755, parents=True, exist_ok=True)
    with open(confd_path / "machinery_manager.conf", "wt") as fil:
        print("[cuckoo]", file=fil)
        print(f"machinery = {MockMachinery.module_name}", file=fil)
    ConfigMeta.refresh()
    monkeypatch.setattr(MachineryManager, "create_machinery", lambda self: machinery)
    yield MachineryManager()


@pytest.mark.usefixtures("db")
@pytest.fixture
def scheduler():
    return Scheduler()


@pytest.fixture
def task(db: _Database, tmp_path) -> Generator[Task, None, None]:
    sample_path = tmp_path / "sample.py"
    with open(sample_path, "wt") as fil:
        print("#!/usr/bin/env python\nprint('hello world')", file=fil)
    with db.session.begin():
        db.add_path(str(sample_path))
        task = db.list_tasks()[0]
        db.session.expunge_all()

    yield task


@pytest.fixture
def machine(db: _Database) -> Generator[Machine, None, None]:
    with db.session.begin():
        machine = db.add_machine(
            name="name0",
            label="label0",
            arch="x64",
            ip="1.2.3.4",
            platform="windows",
            tags="tag1,x64",
            interface="int0",
            snapshot="snap0",
            resultserver_ip="5.6.7.8",
            resultserver_port="2043",
            reserved=False,
        )
        db.session.expunge_all()
    yield machine


def get_test_object_path(relpath: str):
    result = pathlib.Path(__file__).absolute().parent / relpath
    if not result.exists():
        pytest.skip("Required data file is not present")
    return result


@pytest.mark.usefixtures("db")
class TestAnalysisManager:
    def test_init(self, task: Task):
        mgr = AnalysisManager(task=task)

        assert mgr.cfg.cuckoo == {
            "allow_static": False,
            "categories": "static, pcap, url, file",
            "freespace": 50000,
            "delete_original": False,
            "tmppath": "/tmp",
            "terminate_processes": False,
            "memory_dump": False,
            "delete_bin_copy": False,
            "max_machines_count": 10,
            "reschedule": False,
            "rooter": "/tmp/cuckoo-rooter",
            "machinery": "kvm",
            "machinery_screenshots": False,
            "delete_archive": True,
            "max_vmstartup_count": 5,
            "daydelta": 0,
            "max_analysis_count": 0,
            "max_len": 196,
            "sanitize_len": 32,
            "sanitize_to_len": 24,
            "scaling_semaphore": False,
            "scaling_semaphore_update_timer": 10,
            "freespace_processing": 15000,
            "periodic_log": False,
            "fail_unserviceable": True,
        }

        assert mgr.task.id == task.id

    def test_logger(self, task: Task, caplog: pytest.LogCaptureFixture):
        mgr = AnalysisManager(task=task)
        with caplog.at_level(logging.INFO):
            mgr.log.info("Test")
        assert any((record.message == f"Task #{task.id}: Test") for record in caplog.records)

    def test_prepare_task_and_machine_to_start_no_machinery(self, db: _Database, task: Task):
        mgr = AnalysisManager(task=task)
        assert task.status != TASK_RUNNING
        with db.session.begin():
            mgr.prepare_task_and_machine_to_start()
        with db.session.begin():
            db.session.refresh(task)
            assert task.status == TASK_RUNNING

    def test_prepare_task_and_machine_to_start_with_machinery(
        self, db: _Database, task: Task, machine: Machine, machinery_manager: MachineryManager
    ):
        mgr = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        with db.session.begin():
            mgr.prepare_task_and_machine_to_start()
        with db.session.begin():
            db.session.refresh(task)
            db.session.refresh(machine)
            guest: Guest = db.session.query(Guest).first()
            assert task.status == TASK_RUNNING
            assert task.machine == machine.label
            assert task.machine_id == machine.id
            assert machine.locked
            assert guest is not None
            assert guest.name == machine.name
            assert guest.label == machine.label
            assert guest.manager == "MockMachinery"
            assert guest.task_id == task.id

    def test_init_storage(self, task: Task, tmp_cuckoo_root: pathlib.Path):
        analysis_man = AnalysisManager(task=task)
        assert analysis_man.init_storage() is True
        assert (tmp_cuckoo_root / "storage" / "analyses" / str(task.id)).exists()

    def test_init_storage_already_exists(self, task: Task, tmp_cuckoo_root: pathlib.Path, caplog: pytest.LogCaptureFixture):
        analysis_man = AnalysisManager(task=task)
        (tmp_cuckoo_root / "storage" / "analyses" / str(task.id)).mkdir(parents=True)
        assert analysis_man.init_storage() is False
        assert "already exists at path" in caplog.text

    def test_init_storage_other_error(self, task: Task, mocker: MockerFixture, caplog: pytest.LogCaptureFixture):
        mocker.patch("lib.cuckoo.common.path_utils.Path.mkdir", side_effect=OSError)
        analysis_man = AnalysisManager(task=task)
        assert analysis_man.init_storage() is False
        assert "Unable to create analysis folder" in caplog.text

    def test_check_file(self, task: Task, mocker: MockerFixture):
        class mock_sample:
            sha256 = "e3b"

        analysis_man = AnalysisManager(task=task)
        mocker.patch("lib.cuckoo.core.database._Database.view_sample", return_value=mock_sample())
        assert analysis_man.check_file("e3b") is True

    def test_check_file_err(self, task: Task, mocker: MockerFixture):
        class mock_sample:
            sha256 = "different_sha_256"

        analysis_man = AnalysisManager(task=task)
        mocker.patch("lib.cuckoo.core.database._Database.view_sample", return_value=mock_sample())
        assert analysis_man.check_file("e3b") is False

    def test_store_file(self, task: Task, tmp_cuckoo_root: pathlib.Path):
        analysis_man = AnalysisManager(task=task)
        analysis_man.init_storage()
        assert analysis_man.store_file(sha256="e3") is True
        assert (tmp_cuckoo_root / "storage" / "binaries" / "e3").exists()
        binary_symlink = tmp_cuckoo_root / "storage" / "analyses" / str(task.id) / "binary"
        assert binary_symlink.is_symlink()
        assert os.readlink(binary_symlink) == str(tmp_cuckoo_root / "storage" / "binaries" / "e3")

    def test_store_file_no_dir(self, task: Task, mocker: MockerFixture, caplog: pytest.LogCaptureFixture):
        analysis_man = AnalysisManager(task=task)
        analysis_man.init_storage()
        mocker.patch("lib.cuckoo.core.analysis_manager.shutil.copy", side_effect=IOError)
        assert analysis_man.store_file(sha256="e3be3b") is False
        assert "Unable to store file" in caplog.text

    def test_store_file_wrong_path(self, task: Task, caplog: pytest.LogCaptureFixture):
        task.target = "idontexist"
        analysis_man = AnalysisManager(task=task)
        analysis_man.init_storage()
        assert analysis_man.store_file(sha256="e3be3b") is False
        assert "analysis aborted" in caplog.text

    def test_store_file_binary_already_exists(self, task: Task, tmp_cuckoo_root: pathlib.Path, caplog: pytest.LogCaptureFixture):
        analysis_man = AnalysisManager(task=task)
        analysis_man.init_storage()
        bin_path = tmp_cuckoo_root / "storage" / "binaries" / "sha256"
        bin_path.parent.mkdir()
        bin_path.touch()
        with caplog.at_level(logging.INFO):
            assert analysis_man.store_file(sha256="sha256") is True
        assert "File already exists" in caplog.text
        assert os.readlink(tmp_cuckoo_root / "storage" / "analyses" / str(task.id) / "binary") == str(bin_path)

    def test_screenshot_machine(
        self,
        task: Task,
        machine: Machine,
        machinery_manager: MachineryManager,
        tmp_cuckoo_root: pathlib.Path,
        custom_conf_path: pathlib.Path,
        monkeypatch,
    ):
        screenshot_called = False
        with open(custom_conf_path / "cuckoo.conf", "wt") as fil:
            print("[cuckoo]\nmachinery_screenshots = on", file=fil)
        ConfigMeta.refresh()

        def screenshot(self2, label, path):
            nonlocal screenshot_called
            screenshot_called = True
            assert label == machine.label
            assert path == str(tmp_cuckoo_root / "storage" / "analyses" / str(task.id) / "shots" / "0001.jpg")

        monkeypatch.setattr(MockMachinery, "screenshot", screenshot)

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        analysis_man.init_storage()
        analysis_man.screenshot_machine()
        assert screenshot_called

    def test_screenshot_machine_disabled(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, custom_conf_path: pathlib.Path, monkeypatch
    ):
        def screenshot(self2, label, path):
            raise RuntimeError("This should not get called.")

        monkeypatch.setattr(MockMachinery, "screenshot", screenshot)

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        analysis_man.init_storage()
        analysis_man.screenshot_machine()

    def test_screenshot_machine_no_machine(
        self, task: Task, custom_conf_path: pathlib.Path, monkeypatch, caplog: pytest.LogCaptureFixture
    ):
        with open(custom_conf_path / "cuckoo.conf", "wt") as fil:
            print("[cuckoo]\nmachinery_screenshots = on", file=fil)
        ConfigMeta.refresh()

        def screenshot(self2, label, path):
            raise RuntimeError("This should not get called.")

        monkeypatch.setattr(MockMachinery, "screenshot", screenshot)

        analysis_man = AnalysisManager(task=task)
        analysis_man.init_storage()
        analysis_man.screenshot_machine()
        assert "no machine is used" in caplog.text

    def test_build_options(
        self, db: _Database, tmp_path: pathlib.Path, task: Task, machine: Machine, machinery_manager: MachineryManager
    ):
        with db.session.begin():
            task = db.session.merge(task)
            task.package = "foo"
            task.options = "foo=bar"
            task.enforce_timeout = 1
            task.clock = datetime.datetime.strptime("01-01-2099 09:01:01", "%m-%d-%Y %H:%M:%S")
            task.timeout = 10

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        opts = analysis_man.build_options()
        assert opts == {
            "amsi": False,
            "browser": True,
            "browsermonitor": False,
            "category": "file",
            "clock": datetime.datetime(2099, 1, 1, 9, 1, 1),
            "curtain": False,
            "digisig": True,
            "disguise": True,
            "do_upload_max_size": 0,
            "during_script": False,
            "enable_trim": 0,
            "enforce_timeout": 1,
            "evtx": False,
            "exports": "",
            "filecollector": True,
            "file_name": "sample.py",
            "file_pickup": False,
            "file_type": "Python script, ASCII text executable",
            "human_linux": False,
            "human_windows": True,
            "id": task.id,
            "ip": "5.6.7.8",
            "options": "foo=bar",
            "package": "foo",
            "permissions": False,
            "port": "2043",
            "pre_script": False,
            "procmon": False,
            "recentfiles": False,
            "screenshots_linux": True,
            "screenshots_windows": True,
            "sslkeylogfile": False,
            "sysmon_linux": False,
            "sysmon_windows": False,
            "target": str(tmp_path / "sample.py"),
            "terminate_processes": False,
            "timeout": 10,
            "tlsdump": True,
            "tracee_linux": False,
            "upload_max_size": 100000000,
            "usage": False,
            "windows_static_route": False,
        }

    def test_build_options_pe(
        self, db: _Database, tmp_path: pathlib.Path, task: Task, machine: Machine, machinery_manager: MachineryManager
    ):
        sample_location = get_test_object_path(
            pathlib.Path("data/core/5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b")
        )
        with db.session.begin():
            task = db.session.merge(task)
            task.package = "file"
            task.enforce_timeout = 1
            task.clock = datetime.datetime.strptime("01-01-2099 09:01:01", "%m-%d-%Y %H:%M:%S")
            task.timeout = 10
            task.target = str(sample_location)

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        opts = analysis_man.build_options()
        assert opts == {
            "amsi": False,
            "browser": True,
            "browsermonitor": False,
            "category": "file",
            "clock": datetime.datetime(2099, 1, 1, 9, 1, 1),
            "curtain": False,
            "digisig": True,
            "disguise": True,
            "do_upload_max_size": 0,
            "during_script": False,
            "enable_trim": 0,
            "enforce_timeout": 1,
            "evtx": False,
            "exports": "",
            "filecollector": True,
            "file_name": sample_location.name,
            "file_pickup": False,
            "file_type": "PE32 executable (console) Intel 80386, for MS Windows",
            "human_linux": False,
            "human_windows": True,
            "id": task.id,
            "ip": "5.6.7.8",
            "options": "",
            "package": "file",
            "permissions": False,
            "port": "2043",
            "pre_script": False,
            "procmon": False,
            "recentfiles": False,
            "screenshots_linux": True,
            "screenshots_windows": True,
            "sslkeylogfile": False,
            "sysmon_linux": False,
            "sysmon_windows": False,
            "target": str(sample_location),
            "terminate_processes": False,
            "timeout": 10,
            "tlsdump": True,
            "tracee_linux": False,
            "upload_max_size": 100000000,
            "usage": False,
            "windows_static_route": False,
        }

    def test_category_checks(
        self, db: _Database, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        sample_sha256 = "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b"

        class mock_sample:
            sha256 = sample_sha256

        sample_location = get_test_object_path(pathlib.Path("data/core") / sample_sha256)
        with db.session.begin():
            task = db.session.merge(task)
            task.target = str(sample_location)

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        assert analysis_man.init_storage() is True
        mocker.patch("lib.cuckoo.core.database._Database.view_sample", return_value=mock_sample())

        assert analysis_man.category_checks() is None

    def test_category_checks_modified_file(
        self, db: _Database, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        sample_sha256 = "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b"

        class mock_sample:
            sha256 = "123"

        sample_location = get_test_object_path(pathlib.Path("data/core") / sample_sha256)
        with db.session.begin():
            task = db.session.merge(task)
            task.target = str(sample_location)

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        assert analysis_man.init_storage() is True
        mocker.patch("lib.cuckoo.core.database._Database.view_sample", return_value=mock_sample())

        assert analysis_man.category_checks() is False

    def test_category_checks_no_store_file(
        self, db: _Database, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        sample_sha256 = "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b"

        class mock_sample:
            sha256 = sample_sha256

        sample_location = get_test_object_path(pathlib.Path("data/core") / sample_sha256)
        with db.session.begin():
            task = db.session.merge(task)
            task.target = str(sample_location)

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        assert analysis_man.init_storage() is True
        mocker.patch("lib.cuckoo.core.database._Database.view_sample", return_value=mock_sample())
        mocker.patch("lib.cuckoo.core.scheduler.AnalysisManager.store_file", return_value=False)
        assert analysis_man.category_checks() is False

    def test_category_checks_pcap(
        self, db: _Database, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        sample_sha256 = "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b"

        class mock_sample:
            sha256 = sample_sha256

        sample_location = get_test_object_path(pathlib.Path("data/core") / sample_sha256)
        with db.session.begin():
            task = db.session.merge(task)
            task.target = str(sample_location)
            task.category = "pcap"

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        assert analysis_man.init_storage() is True
        mocker.patch("lib.cuckoo.core.database._Database.view_sample", return_value=mock_sample())
        assert analysis_man.category_checks() is True
