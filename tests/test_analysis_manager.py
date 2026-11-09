import datetime
import logging
import os
import pathlib
from typing import Generator

import pytest
from pytest_mock import MockerFixture

from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import Config, ConfigMeta
from lib.cuckoo.core.analysis_manager import AnalysisManager
from lib.cuckoo.core.data.task import TASK_RUNNING, Task, TASK_FAILED_ANALYSIS
from lib.cuckoo.core.data.guests import Guest
from lib.cuckoo.core.data.machines import Machine
from lib.cuckoo.core.database import _Database
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


# @pytest.mark.usefixtures("db")
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


# @pytest.mark.usefixtures("db")
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

        assert mgr.cfg.cuckoo == Config("cuckoo").cuckoo

        assert mgr.task.id == task.id

    def test_logger(self, task: Task, caplog: pytest.LogCaptureFixture):
        mgr = AnalysisManager(task=task)
        with caplog.at_level(logging.INFO):
            mgr.log.info("Test")
        assert any((record.message == f"Task #{task.id}: Test") for record in caplog.records)

    def test_logger_with_main_task_id(self, task: Task, caplog: pytest.LogCaptureFixture):
        task.set_attribute("main_task_id", 9001)
        mgr = AnalysisManager(task=task)
        with caplog.at_level(logging.INFO):
            mgr.log.info("Distributed test")
        matching = [r for r in caplog.records if r.message == f"Task #{task.id} (9001): Distributed test"]
        assert len(matching) == 1
        assert getattr(matching[0], "task_id", None) == task.id
        assert getattr(matching[0], "main_task_id", None) == 9001

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
            logging.info(machine)
            guest: Guest = db.session.scalar(select(Guest))
            assert task.status == TASK_RUNNING
            assert task.machine == machine.label
            # ToDo fix, idk why this one fails
            # assert task.machine_id == machine.id
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
        self,
        db: _Database,
        tmp_path: pathlib.Path,
        task: Task,
        machine: Machine,
        machinery_manager: MachineryManager,
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

        expected_opts = {
            "category": "file",
            "clock": datetime.datetime(2099, 1, 1, 9, 1, 1),
            "do_upload_max_size": 0,
            "enable_trim": 0,
            "enforce_timeout": 1,
            "exports": "",
            "file_name": "sample.py",
            "file_type": "Python script, ASCII text executable",
            "id": task.id,
            "ip": "5.6.7.8",
            "options": "foo=bar",
            "package": "foo",
            "port": "2043",
            "target": str(tmp_path / "sample.py"),
            "terminate_processes": False,
            "timeout": 10,
            "upload_max_size": 100000000,
        }
        # Dynamically load auxiliary modules from Config to ensure test stays in sync with configuration changes
        expected_opts.update(Config("auxiliary").auxiliary_modules)

        assert opts == expected_opts

    def test_build_options_pe(
        self,
        db: _Database,
        tmp_path: pathlib.Path,
        task: Task,
        machine: Machine,
        machinery_manager: MachineryManager,
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

        expected_opts = {
            "category": "file",
            "clock": datetime.datetime(2099, 1, 1, 9, 1, 1),
            "do_upload_max_size": 0,
            "enable_trim": 0,
            "enforce_timeout": 1,
            "exports": "",
            "file_name": sample_location.name,
            "file_type": "PE32 executable (console) Intel 80386, for MS Windows",
            "id": task.id,
            "ip": "5.6.7.8",
            "options": "",
            "package": "file",
            "port": "2043",
            "target": str(sample_location),
            "terminate_processes": False,
            "timeout": 10,
            "upload_max_size": 100000000,
        }
        # Dynamically load auxiliary modules from Config to ensure test stays in sync with configuration changes
        expected_opts.update(Config("auxiliary").auxiliary_modules)

        assert opts == expected_opts


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

    def test_machine_running_finally_cleanup(
        self, db: _Database, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        """Verify that machine_running stops and releases the machine even if an unhandled exception is raised in yield."""
        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)

        # Mock machinery manager functions
        mock_start = mocker.patch.object(machinery_manager, "start_machine")
        mock_stop = mocker.patch.object(machinery_manager, "stop_machine")
        mock_release = mocker.patch.object(machinery_manager.machinery, "release")

        guest = mocker.MagicMock()
        guest.id = 123
        analysis_man.guest = guest

        with pytest.raises(RuntimeError, match="Simulated unhandled exception"):
            with analysis_man.machine_running():
                raise RuntimeError("Simulated unhandled exception")

        # Verify stop and release are still cleanly called on unhandled exceptions
        assert mock_start.called
        assert mock_stop.called
        assert mock_release.called

    def test_launch_analysis_unexpected_exception(
        self, db: _Database, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        """Verify that launch_analysis handles unexpected exceptions by setting status to failed and unlocking the machine."""
        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)

        # Force perform_analysis to raise an unhandled exception
        mocker.patch.object(analysis_man, "perform_analysis", side_effect=RuntimeError("Unexpected perform_analysis error"))
        mock_unlock = mocker.patch("lib.cuckoo.core.database._Database.unlock_machine")
        mock_log_exception = mocker.patch.object(analysis_man.log, "exception")

        with pytest.raises(RuntimeError, match="Unexpected perform_analysis error"):
            analysis_man.launch_analysis()

        # Verify task is flagged failed and machine is unlocked
        with db.session.begin():
            db_task = db.view_task(task.id)
            assert db_task.status == TASK_FAILED_ANALYSIS
        assert mock_unlock.called
        assert mock_log_exception.called

    def test_guest_http_session_retries(self):
        from lib.cuckoo.core.guest import GuestManager

        session = GuestManager._guest_http_session()
        adapter = session.get_adapter("http://10.0.0.2:8000/status")
        assert adapter.max_retries.total == 3
        assert adapter.max_retries.connect == 3
        assert adapter.max_retries.read == 2

    def test_run_suppresses_dead_machine_traceback(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture, caplog: pytest.LogCaptureFixture
    ):
        from lib.cuckoo.common.exceptions import CuckooMachineError

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        mocker.patch.object(
            analysis_man,
            "launch_analysis",
            side_effect=CuckooMachineError("Unable to restore snapshot on virtual machine label0"),
        )
        with caplog.at_level(logging.ERROR):
            analysis_man.run()

        records = [r for r in caplog.records if "failure in AnalysisManager.run" in r.message]
        assert len(records) == 1
        assert records[0].exc_info is None

    def test_network_routing_logs_unroute_rooter_error(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture, caplog: pytest.LogCaptureFixture
    ):
        """A rooter error during teardown is logged once, without traceback, and not propagated."""
        from lib.cuckoo.common.exceptions import CuckooRooterError

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        mocker.patch.object(analysis_man, "route_network")
        mocker.patch.object(analysis_man, "unroute_network", side_effect=CuckooRooterError("/tmp/cuckoo-rooter response timeout"))

        with caplog.at_level(logging.ERROR):
            with analysis_man.network_routing():
                pass

        records = [r for r in caplog.records if "Failed to fully unroute network" in r.message]
        assert len(records) == 1
        assert "response timeout" in records[0].message
        assert records[0].exc_info is None

    def test_network_routing_unroutes_after_partial_route_failure(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        """If route_network fails part-way, unroute_network still runs and the setup error propagates."""
        from lib.cuckoo.common.exceptions import CuckooRooterError

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        mocker.patch.object(analysis_man, "route_network", side_effect=CuckooRooterError("setup timeout"))
        mock_unroute = mocker.patch.object(analysis_man, "unroute_network", side_effect=CuckooRooterError("teardown timeout"))
        body = mocker.MagicMock()

        with pytest.raises(CuckooRooterError, match="setup timeout"):
            with analysis_man.network_routing():
                body()

        assert mock_unroute.called
        assert not body.called

    def test_network_routing_unexpected_unroute_error_does_not_mask_body_error(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture, caplog: pytest.LogCaptureFixture
    ):
        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        mocker.patch.object(analysis_man, "route_network")
        mocker.patch.object(analysis_man, "unroute_network", side_effect=KeyError("boom"))

        with caplog.at_level(logging.ERROR):
            with pytest.raises(RuntimeError, match="analysis failed"):
                with analysis_man.network_routing():
                    raise RuntimeError("analysis failed")

        records = [r for r in caplog.records if "Unexpected error while unrouting network" in r.message]
        assert len(records) == 1
        assert records[0].exc_info is not None

    def test_unroute_network_is_best_effort(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        """One failing teardown command must not skip the rest; all failures are reported together."""
        from lib.cuckoo.common.exceptions import CuckooRooterError

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        analysis_man.socks5s = {}
        analysis_man.route = "internet"
        analysis_man.interface = "eth9"
        analysis_man.rt_table = "main"
        analysis_man.reject_segments = "10.0.0.0/8"
        analysis_man.reject_hostports = "22"
        analysis_man.no_local_routing = False

        failing = {"libvirt_fwo_disable", "forward_reject_disable"}

        def fake_rooter(command, *args, **kwargs):
            if command in failing:
                return {"output": "", "exception": f"{command} timeout"}
            return {"output": "", "exception": None}

        mock_rooter = mocker.patch("lib.cuckoo.core.analysis_manager.rooter", side_effect=fake_rooter)

        with pytest.raises(CuckooRooterError) as excinfo:
            analysis_man.unroute_network()

        sent = [c.args[0] for c in mock_rooter.call_args_list]
        assert sent == [
            "libvirt_fwo_disable",
            "forward_disable",
            "forward_reject_disable",
            "hostports_reject_disable",
            "srcroute_disable",
        ]
        assert "libvirt_fwo_disable: libvirt_fwo_disable timeout" in str(excinfo.value)
        assert "forward_reject_disable: forward_reject_disable timeout" in str(excinfo.value)

    def test_unroute_network_success_does_not_raise(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        analysis_man.socks5s = {}
        analysis_man.route = "none"
        mock_rooter = mocker.patch(
            "lib.cuckoo.core.analysis_manager.rooter", return_value={"output": "", "exception": None}
        )
        analysis_man.unroute_network()
        assert [c.args[0] for c in mock_rooter.call_args_list] == ["drop_disable"]

    def test_launch_analysis_rooter_error_logged_without_traceback(
        self,
        db: _Database,
        task: Task,
        machine: Machine,
        machinery_manager: MachineryManager,
        mocker: MockerFixture,
        caplog: pytest.LogCaptureFixture,
    ):
        """CuckooRooterError: task failed, machine unlocked, single log line without traceback."""
        from lib.cuckoo.common.exceptions import CuckooRooterError

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        mocker.patch.object(
            analysis_man, "perform_analysis", side_effect=CuckooRooterError("Error execution rooter command: response timeout")
        )
        mock_unlock = mocker.patch("lib.cuckoo.core.database._Database.unlock_machine")

        with caplog.at_level(logging.ERROR):
            with pytest.raises(CuckooRooterError):
                analysis_man.launch_analysis()

        with db.session.begin():
            assert db.view_task(task.id).status == TASK_FAILED_ANALYSIS
        assert mock_unlock.called
        records = [r for r in caplog.records if "Rooter error during analysis" in r.message]
        assert len(records) == 1
        assert records[0].exc_info is None

    def test_launch_analysis_other_critical_error_keeps_traceback(
        self, db: _Database, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        """Non-rooter CuckooCriticalError subclasses are still logged with a traceback."""
        from lib.cuckoo.common.exceptions import CuckooDatabaseError

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        mocker.patch.object(analysis_man, "perform_analysis", side_effect=CuckooDatabaseError("db gone"))
        mocker.patch("lib.cuckoo.core.database._Database.unlock_machine")
        mock_log_exception = mocker.patch.object(analysis_man.log, "exception")

        with pytest.raises(CuckooDatabaseError):
            analysis_man.launch_analysis()

        assert mock_log_exception.called

    def test_run_rooter_error_logged_once(
        self,
        task: Task,
        machine: Machine,
        machinery_manager: MachineryManager,
        mocker: MockerFixture,
        caplog: pytest.LogCaptureFixture,
    ):
        """launch_analysis logs the rooter error; run() must not log it a second time."""
        from lib.cuckoo.common.exceptions import CuckooRooterError

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        mocker.patch.object(analysis_man, "perform_analysis", side_effect=CuckooRooterError("response timeout"))
        mocker.patch("lib.cuckoo.core.database._Database.unlock_machine")

        with caplog.at_level(logging.INFO):
            analysis_man.run()

        error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert len(error_records) == 1
        assert "Rooter error during analysis" in error_records[0].message
        assert not any("failure in AnalysisManager.run" in r.message for r in caplog.records)

    @staticmethod
    def _fake_routing(route="none", internet="none"):
        from types import SimpleNamespace

        return SimpleNamespace(
            routing=SimpleNamespace(
                route=route,
                internet=internet,
                rt_table="main",
                no_local_routing=False,
                nat=True,
                reject_segments="none",
                reject_hostports="none",
                verify_interface=False,
            ),
            inetsim=SimpleNamespace(enabled=False),
            tor=SimpleNamespace(enabled=False),
            vpn=SimpleNamespace(enabled=False),
            socks5=SimpleNamespace(enabled=False),
        )

    def _routing_manager(self, task, machine, machinery_manager, mocker, route, internet="none"):
        from types import SimpleNamespace

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        analysis_man.socks5s = {}
        mocker.patch.object(analysis_man, "task", SimpleNamespace(route=None, id=task.id))
        mocker.patch.object(machine, "resultserver_port", 2042, create=True)
        mocker.patch("lib.cuckoo.core.analysis_manager.Config", return_value=self._fake_routing(route, internet))
        return analysis_man

    def test_route_network_detects_missing_nic(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        """nic_available returning output False must switch to route=none (rooter() returns a dict, which is always truthy)."""
        analysis_man = self._routing_manager(task, machine, machinery_manager, mocker, route="internet", internet="eth9")

        def fake_rooter(command, *args, **kwargs):
            if command == "nic_available":
                return {"output": False, "exception": None}
            return {"output": None, "exception": None}

        mock_rooter = mocker.patch("lib.cuckoo.core.analysis_manager.rooter", side_effect=fake_rooter)
        analysis_man.route_network()

        assert analysis_man.route == "none"
        assert analysis_man.interface is None
        assert [c.args[0] for c in mock_rooter.call_args_list] == ["nic_available", "drop_enable"]

    def test_route_network_available_nic_keeps_route(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        analysis_man = self._routing_manager(task, machine, machinery_manager, mocker, route="internet", internet="eth9")
        mocker.patch(
            "lib.cuckoo.core.analysis_manager.rooter",
            side_effect=lambda command, *a, **k: {"output": command == "nic_available", "exception": None},
        )
        analysis_man.route_network()
        assert analysis_man.route == "internet"
        assert analysis_man.interface == "eth9"

    @pytest.mark.parametrize("route_val", ["none", False])
    def test_route_network_drop_without_required_rooter(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture, route_val
    ):
        """Default configuration: no rooter running and none required -> route=none/false proceeds without drop rules."""
        from lib.cuckoo.core.rooter import ROOTER_UNAVAILABLE

        analysis_man = self._routing_manager(task, machine, machinery_manager, mocker, route=route_val)
        mocker.patch("lib.cuckoo.core.analysis_manager.rooter_required", return_value=False)
        mocker.patch(
            "lib.cuckoo.core.analysis_manager.rooter",
            return_value={"output": None, "exception": "rooter is not reachable", ROOTER_UNAVAILABLE: True},
        )
        analysis_man.route_network()
        assert analysis_man.rooter_response is None

    def test_route_network_drop_fails_closed_when_rooter_required(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        """Rooter required but unreachable: drop rules were not applied, so the analysis must not start."""
        from lib.cuckoo.common.exceptions import CuckooRooterError
        from lib.cuckoo.core.rooter import ROOTER_UNAVAILABLE

        analysis_man = self._routing_manager(task, machine, machinery_manager, mocker, route="none")
        mocker.patch("lib.cuckoo.core.analysis_manager.rooter_required", return_value=True)
        mocker.patch(
            "lib.cuckoo.core.analysis_manager.rooter",
            return_value={"output": None, "exception": "rooter is not reachable", ROOTER_UNAVAILABLE: True},
        )
        with pytest.raises(CuckooRooterError, match="not reachable"):
            analysis_man.route_network()

    @pytest.mark.parametrize("required", [False, True])
    def test_unroute_network_rooter_unavailable(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture, required: bool
    ):
        from lib.cuckoo.common.exceptions import CuckooRooterError
        from lib.cuckoo.core.rooter import ROOTER_UNAVAILABLE

        analysis_man = self._routing_manager(task, machine, machinery_manager, mocker, route="none")
        analysis_man.route = "none"
        mocker.patch("lib.cuckoo.core.analysis_manager.rooter_required", return_value=required)
        mocker.patch(
            "lib.cuckoo.core.analysis_manager.rooter",
            return_value={"output": None, "exception": "rooter is not reachable", ROOTER_UNAVAILABLE: True},
        )
        if required:
            with pytest.raises(CuckooRooterError, match="drop_disable"):
                analysis_man.unroute_network()
        else:
            analysis_man.unroute_network()

    def test_route_network_nic_available_error_fails_closed_without_downgrade(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        """A rooter error or timeout on nic_available must raise CuckooRooterError, not silently downgrade to route=none."""
        from lib.cuckoo.common.exceptions import CuckooRooterError
        from lib.cuckoo.core.rooter import ROOTER_UNAVAILABLE

        analysis_man = self._routing_manager(task, machine, machinery_manager, mocker, route="internet", internet="eth9")
        mocker.patch("lib.cuckoo.core.analysis_manager.rooter_required", return_value=False)
        mock_rooter = mocker.patch(
            "lib.cuckoo.core.analysis_manager.rooter",
            return_value={"output": None, "exception": "rooter is not reachable", ROOTER_UNAVAILABLE: True},
        )

        with pytest.raises(CuckooRooterError, match="not reachable"):
            with analysis_man.network_routing():
                pass

        # Only nic_available was called; neither drop_enable nor unroute teardown commands were sent.
        assert [c.args[0] for c in mock_rooter.call_args_list] == ["nic_available"]
        assert analysis_man.route is None
        assert analysis_man.interface is None

    def test_route_network_explicit_drop_fails_closed_even_when_rooter_not_globally_required(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        """An explicit route='drop' requires drop_enable rules and must fail closed when the rooter is unavailable."""
        from lib.cuckoo.common.exceptions import CuckooRooterError
        from lib.cuckoo.core.rooter import ROOTER_UNAVAILABLE

        analysis_man = self._routing_manager(task, machine, machinery_manager, mocker, route="drop")
        mocker.patch("lib.cuckoo.core.analysis_manager.rooter_required", return_value=False)
        mocker.patch(
            "lib.cuckoo.core.analysis_manager.rooter",
            return_value={"output": None, "exception": "rooter is not reachable", ROOTER_UNAVAILABLE: True},
        )
        with pytest.raises(CuckooRooterError, match="not reachable"):
            analysis_man.route_network()

    @pytest.mark.parametrize(
        "failing_cmd,call_index",
        [
            ("libvirt_fwo_enable", 0),
            ("forward_enable", 0),
            ("forward_enable", 2),
            ("add_dev_to_vrf", 0),
        ],
    )
    def test_route_network_checks_intermediate_rooter_calls(
        self,
        task: Task,
        machine: Machine,
        machinery_manager: MachineryManager,
        mocker: MockerFixture,
        failing_cmd: str,
        call_index: int,
    ):
        """Intermediate rooter() calls in route_network must not have their errors overwritten by later calls."""
        from types import SimpleNamespace

        from lib.cuckoo.common.exceptions import CuckooRooterError

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        analysis_man.socks5s = {}
        mocker.patch.object(analysis_man, "task", SimpleNamespace(route=None, id=task.id))
        mocker.patch.object(machine, "resultserver_port", 2042, create=True)
        mocker.patch(
            "lib.cuckoo.core.analysis_manager.Config",
            return_value=SimpleNamespace(
                routing=SimpleNamespace(
                    route="internet",
                    internet="eth9",
                    rt_table="main",
                    no_local_routing=True,
                    nat=False,
                    reject_segments="none",
                    reject_hostports="none",
                    verify_interface=False,
                ),
                inetsim=SimpleNamespace(enabled=False),
                tor=SimpleNamespace(enabled=False),
                vpn=SimpleNamespace(enabled=False),
                socks5=SimpleNamespace(enabled=False),
            ),
        )
        counts: dict[str, int] = {}

        def fake_rooter(command, *args, **kwargs):
            idx = counts.get(command, 0)
            counts[command] = idx + 1
            if command == "nic_available":
                return {"output": True, "exception": None}
            if command == failing_cmd and idx == call_index:
                return {"output": "", "exception": f"{command}#{idx} failed"}
            return {"output": "", "exception": None}

        mocker.patch("lib.cuckoo.core.analysis_manager.rooter", side_effect=fake_rooter)

        with pytest.raises(CuckooRooterError, match=f"{failing_cmd}#{call_index} failed"):
            analysis_man.route_network()

    def test_route_network_socks5_enable_error_not_masked_by_fwo(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        from types import SimpleNamespace

        from lib.cuckoo.common.exceptions import CuckooRooterError

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        analysis_man.socks5s = {"proxy1": {"dnsport": 5353, "port": 1080}}
        mocker.patch.object(analysis_man, "task", SimpleNamespace(route="proxy1", id=task.id))
        mocker.patch.object(machine, "resultserver_port", 2042, create=True)

        def fake_rooter(command, *args, **kwargs):
            if command == "socks5_enable":
                return {"output": "", "exception": "socks5_enable failed"}
            return {"output": "", "exception": None}

        mock_rooter = mocker.patch("lib.cuckoo.core.analysis_manager.rooter", side_effect=fake_rooter)

        with pytest.raises(CuckooRooterError, match="socks5_enable failed"):
            analysis_man.route_network()

        assert [c.args[0] for c in mock_rooter.call_args_list] == ["socks5_enable"]

    def test_guest_manager_db_retry_on_operational_error(self, monkeypatch, mocker):
        from lib.cuckoo.core.guest import GuestManager, db

        monkeypatch.setattr("time.sleep", lambda s: None)
        gm = GuestManager(vm_id="label0", ip="1.2.3.4", platform="windows", task_id=1, analysis_manager=None)

        # Test get_status_from_db retries on OperationalError
        mock_remove = mocker.patch.object(db.session, "remove")
        mock_dispose = mocker.patch.object(db.engine, "dispose")
        attempts = 0

        def fake_guest_get_status(task_id):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OperationalError("SELECT 1", {}, Exception("server closed connection"))
            return "running"

        mocker.patch.object(db, "guest_get_status", side_effect=fake_guest_get_status)
        status = gm.get_status_from_db()
        assert status == "running"
        assert attempts == 2
        assert mock_remove.call_count >= 1
        assert mock_dispose.call_count == 0

        # Test set_status_in_db retries on OperationalError
        attempts = 0

        def fake_guest_set_status(task_id, new_status):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OperationalError("UPDATE 1", {}, Exception("server closed connection"))

        mocker.patch.object(db, "guest_set_status", side_effect=fake_guest_set_status)
        gm.set_status_in_db("completed")
        assert attempts == 2
        assert mock_remove.call_count >= 2
        assert mock_dispose.call_count == 0

    def test_guest_manager_wait_for_completion_resilient_to_db_error(self, monkeypatch, mocker):
        from lib.cuckoo.core.guest import GuestManager

        monkeypatch.setattr("time.sleep", lambda s: None)
        gm = GuestManager(vm_id="label0", ip="1.2.3.4", platform="windows", task_id=1, analysis_manager=None)
        gm.timeout = 10

        # Simulate get_status_from_db raising OperationalError on first call, then returning "stopping"
        call_count = 0

        def fake_get_status():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OperationalError("SELECT 1", {}, Exception("transient failure"))
            return "stopping"

        mocker.patch.object(gm, "get_status_from_db", side_effect=fake_get_status)
        gm.wait_for_completion()
        assert call_count == 2

    def test_guest_manager_wait_for_completion_hard_limit_with_persistent_db_error(self, monkeypatch, mocker):
        """A database that never comes back must not keep wait_for_completion looping past the hard limit."""
        import lib.cuckoo.core.guest as guest_mod
        from lib.cuckoo.core.guest import GuestManager

        monkeypatch.setattr("time.sleep", lambda s: None)
        clock = iter(range(0, 100000, 50))
        monkeypatch.setattr(guest_mod.timeit, "default_timer", lambda: next(clock))
        gm = GuestManager(vm_id="label0", ip="1.2.3.4", platform="windows", task_id=1, analysis_manager=None)
        gm.timeout = 10

        get_status = mocker.patch.object(
            gm, "get_status_from_db", side_effect=OperationalError("SELECT 1", {}, Exception("db down"))
        )
        set_status = mocker.patch.object(gm, "set_status_in_db", side_effect=OperationalError("UPDATE", {}, Exception("db down")))
        gm.wait_for_completion()

        # Ends after a bounded number of polls and tries (best effort) to mark the guest failed.
        assert get_status.call_count < 100
        set_status.assert_called_once_with("failed")

    def test_run_analysis_on_guest_logs_exception_first_and_suppresses_failed_status_error(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        from lib.cuckoo.core.guest import GuestManager

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        mocker.patch.object(analysis_man, "build_options", return_value={"id": task.id})
        mocker.patch.object(GuestManager, "start_analysis")
        mocker.patch.object(GuestManager, "get_status_from_db", return_value="starting")
        mocker.patch.object(GuestManager, "wait_for_completion", side_effect=RuntimeError("Guest crashed"))
        mocker.patch.object(
            GuestManager,
            "set_status_in_db",
            side_effect=[None, OperationalError("UPDATE", {}, Exception("DB down"))],
        )
        mock_log_exception = mocker.patch.object(analysis_man.log, "exception")

        # Must not raise despite set_status_in_db("failed") raising OperationalError
        analysis_man.run_analysis_on_guest()

        # Verify log.exception was called with the guest error
        assert mock_log_exception.called
        log_msg = mock_log_exception.call_args[0][0]
        assert "Unknown exception waiting for guest completion" in log_msg

    def test_perform_analysis_finally_resilient_to_operational_error_on_guest_stop(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture, monkeypatch
    ):
        import contextlib

        monkeypatch.setattr("time.sleep", lambda s: None)
        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        analysis_man.guest = mocker.MagicMock(id=1)

        mocker.patch.object(analysis_man, "init_storage", return_value=True)
        mocker.patch.object(analysis_man, "category_checks", return_value=None)
        mocker.patch.object(machinery_manager, "scale_pool")
        mocker.patch.object(analysis_man, "machine_running", return_value=contextlib.nullcontext())
        mocker.patch.object(analysis_man, "result_server", return_value=contextlib.nullcontext())
        mocker.patch.object(analysis_man, "network_routing", return_value=contextlib.nullcontext())
        mocker.patch.object(analysis_man, "run_auxiliary", return_value=contextlib.nullcontext())
        mocker.patch.object(analysis_man, "run_analysis_on_guest")

        # Mock guest_stop raising OperationalError on attempt 1, succeeding on attempt 2
        stop_attempts = 0

        def fake_guest_stop(guest_id):
            nonlocal stop_attempts
            stop_attempts += 1
            if stop_attempts == 1:
                raise OperationalError("UPDATE guest", {}, Exception("DB reconnecting"))

        mocker.patch.object(analysis_man.db, "guest_stop", side_effect=fake_guest_stop)
        mocker.patch.object(analysis_man.db.session, "remove")
        mock_dispose = mocker.patch.object(analysis_man.db.engine, "dispose")

        succeeded = analysis_man.perform_analysis()
        assert succeeded is True
        assert stop_attempts == 2
        assert mock_dispose.call_count == 0

    def test_machine_running_calls_release_when_stop_machine_raises_operational_error(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture, monkeypatch
    ):
        monkeypatch.setattr("time.sleep", lambda s: None)
        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        analysis_man.guest = mocker.MagicMock(id=1)

        mocker.patch.object(machinery_manager, "start_machine")
        mocker.patch.object(
            machinery_manager,
            "stop_machine",
            side_effect=OperationalError("STOP", {}, Exception("DB down during stop_machine")),
        )

        release_attempts = 0

        def fake_release(m):
            nonlocal release_attempts
            release_attempts += 1
            if release_attempts == 1:
                raise OperationalError("RELEASE", {}, Exception("DB down during release"))

        mock_release = mocker.patch.object(machinery_manager.machinery, "release", side_effect=fake_release)
        mock_remove = mocker.patch.object(analysis_man.db.session, "remove")

        with analysis_man.machine_running():
            pass

        assert release_attempts == 2
        assert mock_release.call_count == 2
        assert mock_remove.call_count >= 1

    def test_launch_analysis_retries_on_operational_error(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture, monkeypatch
    ):
        monkeypatch.setattr("time.sleep", lambda s: None)
        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)

        mocker.patch.object(analysis_man, "perform_analysis", return_value=True)
        mocker.patch.object(analysis_man, "update_latest_symlink")

        set_status_attempts = 0

        def fake_set_status(task_id, status):
            nonlocal set_status_attempts
            set_status_attempts += 1
            if set_status_attempts == 1:
                raise OperationalError("UPDATE", {}, Exception("DB reconnecting"))

        mocker.patch.object(analysis_man.db, "set_status", side_effect=fake_set_status)
        mock_remove = mocker.patch.object(analysis_man.db.session, "remove")

        analysis_man.launch_analysis()

        assert set_status_attempts == 2
        assert mock_remove.call_count >= 1

    def test_scheduler_stuck_vm_kills_once_and_respects_guest_started_on_and_upload_grace(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture, tmp_path: pathlib.Path
    ):
        import queue

        from lib.cuckoo.core.data.db_common import _utcnow_naive
        from lib.cuckoo.core.scheduler import Scheduler

        scheduler = Scheduler()
        scheduler.loop_state = mocker.MagicMock()
        scheduler.max_analysis_count = 0

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        task.timeout = 21600
        # Task started 22160s ago (> 21600 + 60 + 100 + 100 = 21860s),
        # but guest_started_on was only 21700s ago (< 21600 + 60 + 100 = 21760s) due to a 460s sample upload.
        now = _utcnow_naive()
        task.started_on = now - datetime.timedelta(seconds=22160)
        analysis_man.guest_started_on = now - datetime.timedelta(seconds=21700)
        mock_gm = mocker.MagicMock()
        analysis_man.guest_manager = mock_gm
        mock_stop_machine = mocker.patch.object(machinery_manager, "stop_machine")

        scheduler.analysis_threads = [analysis_man]
        mocker.patch.object(scheduler, "wait_for_running_analyses_to_finish")
        mocker.patch.object(scheduler, "is_short_on_disk_space", return_value=False)
        mocker.patch.object(scheduler, "find_next_serviceable_task", return_value=(None, None))

        # Must NOT kill the VM yet because guest_started_on elapsed is 21700s <= 21760s.
        scheduler.do_main_loop_work(queue.Queue())
        assert analysis_man.stuck_vm_killed is False
        mock_stop_machine.assert_not_called()
        mock_gm.stop.assert_not_called()

        # Advance guest_started_on past timeout + critical + stuck_seconds (21800s > 21760s).
        analysis_man.guest_started_on = now - datetime.timedelta(seconds=21800)
        scheduler.do_main_loop_work(queue.Queue())
        assert analysis_man.stuck_vm_killed is True
        mock_stop_machine.assert_called_once_with(machine)
        mock_gm.stop.assert_called_once()

        # Subsequent scheduler cycles must NOT re-kill or spam stack traces for the same task.
        scheduler.do_main_loop_work(queue.Queue())
        assert mock_stop_machine.call_count == 1
        assert mock_gm.stop.call_count == 1

    def test_stopped_by_user_skips_full_memory_dump(
        self, task: Task, machine: Machine, machinery_manager: MachineryManager, mocker: MockerFixture
    ):
        from lib.cuckoo.core.guest import GuestManager

        analysis_man = AnalysisManager(task=task, machine=machine, machinery_manager=machinery_manager)
        analysis_man.cfg.cuckoo.memory_dump = True
        mocker.patch.object(analysis_man, "build_options", return_value={"id": task.id})
        mocker.patch.object(GuestManager, "start_analysis")
        mocker.patch.object(GuestManager, "wait_for_completion")
        mocker.patch.object(GuestManager, "set_status_in_db")
        mocker.patch.object(GuestManager, "get_status_from_db", side_effect=["starting", "stopping"])
        mock_dump_mem = mocker.patch.object(machinery_manager.machinery, "dump_memory")

        analysis_man.run_analysis_on_guest()
        assert analysis_man.stopped_by_user is True

        analysis_man.dump_machine_memory()
        mock_dump_mem.assert_not_called()



