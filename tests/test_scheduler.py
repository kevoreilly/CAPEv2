import os
import queue
import shutil
from datetime import datetime

import pytest
import pytest_asyncio
from func_timeout import FunctionTimedOut, func_timeout
from tcr_misc import get_sample, random_string

import lib.cuckoo.core.scheduler as scheduler
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.path_utils import path_cwd, path_delete, path_exists, path_mkdir, path_object, path_write_file
from lib.cuckoo.core.scheduler import AnalysisManager


class mock_task:
    def __init__(self):
        self.id = 1234
        self.category = "file"
        self.target = __file__
        self.options = "foo=bar"
        self.sample_id = "testid"


@pytest_asyncio.fixture
def grab_sample():
    def _grab_sample(sample_hash):
        sample_location = path_object(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        get_sample(hash=sample_hash, download_location=sample_location)
        return sample_location

    return _grab_sample


@pytest_asyncio.fixture
def setup_machine_lock():
    # See lib.cuckoo.core.scheduler::Scheduler:initialize()
    class mock_lock:
        def acquire(self):
            pass

        def release(self):
            pass

    scheduler.machine_lock = mock_lock()
    yield
    scheduler.machine_lock = None


@pytest_asyncio.fixture
def setup_machinery():
    def _setup_machinery(mach_id):
        scheduler.machinery = mach_id

    yield _setup_machinery
    scheduler.machinery = None


@pytest_asyncio.fixture
def symlink():
    try:
        path_mkdir("fstorage/binaries", exist_ok=True)
    except Exception as e:
        print(("Error setting up, probably fine:" + str(e)))
    tempsym = path_cwd() / "storage/binaries/e3be3b"
    real = "/tmp/" + random_string()
    _ = path_write_file(real, "\x00", mode="text")

    try:
        path_mkdir(path_cwd() / "storage/binaries/", exist_ok=True)
    except Exception as e:
        print(("Error setting up, probably fine:" + str(e)))
    print(path_exists(real), path_exists(tempsym))
    os.symlink(real, tempsym)
    yield
    try:
        path_delete(tempsym)
        path_delete(real)
        path_delete("binary")
    except Exception as e:
        print(("Error cleaning up, probably fine:" + str(e)))


@pytest_asyncio.fixture
def clean_init_storage():
    yield
    try:
        shutil.rmtree(path_cwd() / "storage/analyses/1234")
    except Exception as e:
        print(("Error cleaning up, probably fine:" + str(e)))


@pytest_asyncio.fixture
def create_store_file_dir():
    try:
        path_mkdir(path_cwd() / "storage/binaries/")
    except Exception as e:
        print(("Error setting up, probably fine:" + str(e)))
    yield
    try:
        shutil.rmtree(path_cwd() / "storage/binaries")
    except Exception as e:
        print(("Error cleaning up, probably fine:" + str(e)))


class TestAnalysisManager:
    def test_init(self):
        analysis_man = AnalysisManager(task=mock_task(), error_queue=queue.Queue())

        assert analysis_man.cfg.cuckoo == {
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
            "batch_scheduling": False,
            "max_batch_count": 20,
            "freespace_processing": 15000,
            "periodic_log": False,
            "fail_unserviceable": True,
        }

        assert analysis_man.task.id == 1234

    def test_init_storage(self, clean_init_storage):
        analysis_man = AnalysisManager(task=mock_task(), error_queue=queue.Queue())
        analysis_man.init_storage()
        assert analysis_man.storage.rsplit("/", 1)[-1] == "1234"

    def test_init_storage_already_exists(self, clean_init_storage, caplog):
        analysis_man = AnalysisManager(task=mock_task(), error_queue=queue.Queue())
        path_mkdir(path_cwd() / "storage/analyses/1234")

        analysis_man.init_storage()
        assert "already exists at path" in caplog.text

    @pytest.mark.skip(reason="TODO")
    def test_init_storage_other_error(self, clean_init_storage, mocker, caplog):
        mocker.patch(
            "lib.cuckoo.core.scheduler.create_folder",
            side_effect=CuckooOperationalError("foo"),
        )
        analysis_man = AnalysisManager(task=mock_task(), error_queue=queue.Queue())
        # with pytest.raises(CuckooOperationalError) as exc_info:
        assert analysis_man.init_storage() is False
        assert "Unable to create analysis folder" in caplog.text

    def test_check_file(self, mocker):
        class mock_sample:
            sha256 = "e3b"

        analysis_man = AnalysisManager(task=mock_task(), error_queue=queue.Queue())
        mocker.patch("lib.cuckoo.core.database.Database.view_sample", return_value=mock_sample())
        assert analysis_man.check_file("e3b") is True

    def test_check_file_err(self, mocker):
        class mock_sample:
            sha256 = "f3b"

        analysis_man = AnalysisManager(task=mock_task(), error_queue=queue.Queue())
        mocker.patch("lib.cuckoo.core.database.Database.view_sample", return_value=mock_sample())
        assert analysis_man.check_file("e3b") is False

    @pytest.mark.skip(reason="TODO")
    def test_store_file(self, create_store_file_dir):
        analysis_man = AnalysisManager(task=mock_task(), error_queue=queue.Queue())
        assert analysis_man.store_file(sha256="e3") is True

    @pytest.mark.skip(reason="TODO")
    def test_store_file_no_dir(self, caplog):
        analysis_man = AnalysisManager(task=mock_task(), error_queue=queue.Queue())
        assert analysis_man.store_file(sha256="e3be3b") is False
        assert "Unable to store file" in caplog.text

    def test_store_file_wrong_path(self, caplog):
        mock_task_wrong_path = mock_task()
        mock_task_wrong_path.target += "foobar"
        analysis_man = AnalysisManager(task=mock_task_wrong_path, error_queue=queue.Queue())
        analysis_man.store_file(sha256="e3be3b") is False
        assert "analysis aborted" in caplog.text

    @pytest.mark.skip(reason="TODO")
    def test_store_file_symlink(self, symlink):
        analysis_man = AnalysisManager(task=mock_task(), error_queue=queue.Queue())
        assert analysis_man.store_file(sha256="e3be3b") is True

    @pytest.mark.skip(reason="TODO")
    def test_store_file_symlink_err(self, symlink, caplog):
        _ = path_write_file("binary", b"\x00")
        analysis_man = AnalysisManager(task=mock_task(), error_queue=queue.Queue())
        analysis_man.store_file(sha256="e3be3b")
        assert "Unable to create symlink/copy" in caplog.text

    def test_acquire_machine(self, setup_machinery, setup_machine_lock):
        class mock_machinery:
            def availables(self, label, platform, tags, arch, os_version):
                return True

            def acquire(self, machine_id, platform, tags, arch, os_version):
                class mock_acquire:
                    name = "mock_mach"
                    label = "mock_label"
                    platform = "mock_platform"
                    arch = "x64"

                return mock_acquire()

        class mock_machine:
            machine = "mock"

        class mock_plat:
            platform = "plat"

        class mock_package:
            package = "foo"

        class mock_tags:
            class mock_tag:
                def __init__(self, name):
                    self.name = name

            tags = [mock_tag("tag1"), mock_tag("tag2")]

            def __iter__(self):
                for tag in self.tags:
                    yield tag

        class mock_arch:
            arch = "x64"

        setup_machinery(mock_machinery())
        mock_task_machine = mock_task()
        mock_task_machine.machine = mock_machine()
        mock_task_machine.platform = mock_plat()
        mock_task_machine.tags = mock_tags()
        mock_task_machine.arch = mock_arch()
        mock_task_machine.package = mock_package()

        analysis_man = AnalysisManager(task=mock_task_machine, error_queue=queue.Queue())
        analysis_man.acquire_machine()

        assert analysis_man.machine.name == "mock_mach"

    def test_acquire_machine_machinery_not_avail(self, setup_machinery, setup_machine_lock, mocker):
        class mock_machinery:
            def availables(self):
                return False

            def acquire(self, machine_id, platform, tags):
                class mock_acquire:
                    name = "mock_mach"
                    label = "mock_label"

                return mock_acquire()

        class mock_machine:
            machine = "mock"

        class mock_plat:
            platform = "plat"

        class mock_tags:
            tags = "tags"

        setup_machinery(mock_machinery())
        mock_task_machine = mock_task()
        mock_task_machine.machine = mock_machine()
        mock_task_machine.platform = mock_plat()
        mock_task_machine.tags = mock_tags()

        analysis_man = AnalysisManager(task=mock_task_machine, error_queue=queue.Queue())

        try:
            spy = mocker.spy(scheduler.machine_lock, "release")
            func_timeout(5, analysis_man.acquire_machine)
        except FunctionTimedOut:
            assert spy.call_count >= 4
        except Exception as e:
            print((str(e)))

    def test_acquire_machine_machine_not_avail(self, setup_machinery, setup_machine_lock, mocker):
        class mock_machinery:
            def availables(self):
                return True

            def acquire(self, machine_id, platform, tags):
                return None

        class mock_machine:
            machine = "mock"

        class mock_plat:
            platform = "plat"

        class mock_tags:
            tags = "tags"

        setup_machinery(mock_machinery())
        mock_task_machine = mock_task()
        mock_task_machine.machine = mock_machine()
        mock_task_machine.platform = mock_plat()
        mock_task_machine.tags = mock_tags()

        analysis_man = AnalysisManager(task=mock_task_machine, error_queue=queue.Queue())

        try:
            spy = mocker.spy(scheduler.machine_lock, "release")
            func_timeout(5, analysis_man.acquire_machine)
        except FunctionTimedOut:
            assert spy.call_count >= 4
        except Exception as e:
            print((str(e)))

    def test_build_options(self):
        class mock_machine:
            resultserver_ip = "1.2.3.4"
            resultserver_port = "1337"

        mock_task_build_opts = mock_task()
        mock_task_build_opts.package = "foo"
        mock_task_build_opts.options = "foo=bar"
        mock_task_build_opts.enforce_timeout = 1
        mock_task_build_opts.clock = datetime.strptime("01-01-2099 09:01:01", "%m-%d-%Y %H:%M:%S")
        mock_task_build_opts.timeout = 10

        analysis_man = AnalysisManager(task=mock_task_build_opts, error_queue=queue.Queue())
        analysis_man.machine = mock_machine()
        opts = analysis_man.build_options()
        opts["target"] = opts["target"].rsplit("/", 1)[-1]
        assert opts == {
            "category": "file",
            "exports": "",
            "target": "test_scheduler.py",
            "package": "foo",
            "terminate_processes": False,
            "ip": "1.2.3.4",
            "clock": datetime(2099, 1, 1, 9, 1, 1),
            "enable_trim": 0,
            "port": "1337",
            "file_type": "Python script, ASCII text executable",
            "options": "foo=bar",
            "enforce_timeout": 1,
            "evtx": False,
            "timeout": 10,
            "file_name": "test_scheduler.py",
            "browser": True,
            "curtain": False,
            "procmon": False,
            "digisig": True,
            "disguise": True,
            "sysmon_windows": False,
            "sysmon_linux": False,
            "file_pickup": False,
            "filecollector": True,
            "permissions": False,
            "recentfiles": False,
            "screenshots_linux": True,
            "screenshots_windows": True,
            "tlsdump": True,
            "usage": False,
            "human_linux": False,
            "human_windows": True,
            "stap": False,
            "id": 1234,
            "do_upload_max_size": 0,
            "upload_max_size": 100000000,
            "during_script": False,
            "pre_script": False,
            "windows_static_route": False,
        }

    @pytest.mark.skip(reason="This error is from parse_pe get_exports, which is not part of scheduler anymore")
    def test_build_options_false_pe(self, mocker, caplog):
        class mock_machine(object):
            resultserver_ip = "1.2.3.4"
            resultserver_port = "1337"

        mock_task_build_opts = mock_task()
        mock_task_build_opts.package = "foo"
        mock_task_build_opts.enforce_timeout = 1
        mock_task_build_opts.clock = datetime.strptime("01-01-2099 09:01:01", "%m-%d-%Y %H:%M:%S")
        mock_task_build_opts.timeout = 10

        analysis_man = AnalysisManager(task=mock_task_build_opts, error_queue=queue.Queue())
        analysis_man.machine = mock_machine()
        mocker.patch(
            "lib.cuckoo.core.scheduler.File.get_type", return_value="PE32 executable (console) Intel 80386, for MS Windows"
        )

        opts = analysis_man.build_options()
        opts["target"] = opts["target"].rsplit("/", 1)[-1]
        assert "PE type not recognised" in caplog.text

    @pytest.mark.skip(reason="TODO")
    def test_build_options_pe(self, grab_sample):
        class mock_machine:
            resultserver_ip = "1.2.3.4"
            resultserver_port = "1337"

        sample_location = grab_sample(sample_hash="5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b")
        mock_task_build_opts = mock_task()
        mock_task_build_opts.package = "file"
        mock_task_build_opts.enforce_timeout = 1
        mock_task_build_opts.clock = datetime.strptime("01-01-2099 09:01:01", "%m-%d-%Y %H:%M:%S")
        mock_task_build_opts.timeout = 10
        mock_task_build_opts.target = sample_location

        analysis_man = AnalysisManager(task=mock_task_build_opts, error_queue=queue.Queue())
        analysis_man.machine = mock_machine()
        opts = analysis_man.build_options()
        opts["target"] = opts["target"].rsplit("/", 1)[-1]
        assert opts == {
            "category": "file",
            "exports": "",
            "target": "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b",
            "package": "file",
            "terminate_processes": False,
            "ip": "1.2.3.4",
            "clock": datetime(2099, 1, 1, 9, 1, 1),
            "enable_trim": 0,
            "port": "1337",
            "file_type": "PE32 executable (console) Intel 80386, for MS Windows",
            "options": "foo=bar",
            "enforce_timeout": 1,
            "evtx": False,
            "timeout": 10,
            "file_name": "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b",
            "browser": True,
            "curtain": False,
            "procmon": False,
            "digisig": True,
            "disguise": True,
            "sysmon_windows": False,
            "sysmon_linux": False,
            "filepickup": False,
            "permissions": False,
            "screenshots": True,
            "tlsdump": True,
            "usage": False,
            "human": True,
            "id": 1234,
            "do_upload_max_size": 0,
            "upload_max_size": 100000000,
        }

    @pytest.mark.skip(reason="TODO")
    def test_category_checks(self, clean_init_storage, grab_sample, mocker):
        class mock_sample:
            sha256 = "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b"

        sample_location = grab_sample(sample_hash="5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b")
        mock_task_cat = mock_task()
        mock_task_cat.target = sample_location

        analysis_man = AnalysisManager(task=mock_task_cat, error_queue=queue.Queue())
        assert analysis_man.init_storage() is True
        mocker.patch("lib.cuckoo.core.scheduler.Database.view_sample", return_value=mock_sample())

        assert analysis_man.category_checks() is None

    @pytest.mark.skip(reason="TODO")
    def test_category_checks_modified_file(self, clean_init_storage, mocker):
        class mock_sample:
            sha256 = "123"

        analysis_man = AnalysisManager(task=mock_task(), error_queue=queue.Queue())
        assert analysis_man.init_storage() is True
        mocker.patch("lib.cuckoo.core.scheduler.Database.view_sample", return_value=mock_sample())

        assert analysis_man.category_checks() is False

    @pytest.mark.skip(reason="TODO")
    def test_category_checks_no_store_file(self, clean_init_storage, grab_sample, mocker):
        class mock_sample:
            sha256 = "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b"

        sample_location = grab_sample(sample_hash="5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b")
        mock_task_cat = mock_task()
        mock_task_cat.target = sample_location
        analysis_man = AnalysisManager(task=mock_task_cat, error_queue=queue.Queue())
        assert analysis_man.init_storage() is True
        mocker.patch("lib.cuckoo.core.scheduler.Database.view_sample", return_value=mock_sample())
        mocker.patch("lib.cuckoo.core.scheduler.AnalysisManager.store_file", return_value=False)

        assert analysis_man.category_checks() is False

    @pytest.mark.skip(reason="TODO")
    def test_category_checks_pcap(self, clean_init_storage, grab_sample, mocker):
        class mock_sample:
            sha256 = "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b"

        sample_location = grab_sample(sample_hash="5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b")
        mock_task_cat = mock_task()
        mock_task_cat.target = sample_location
        mock_task_cat.category = "pcap"

        analysis_man = AnalysisManager(task=mock_task_cat, error_queue=queue.Queue())
        assert analysis_man.init_storage() is True
        mocker.patch("lib.cuckoo.core.scheduler.Database.view_sample", return_value=mock_sample())

        assert analysis_man.category_checks() is True
