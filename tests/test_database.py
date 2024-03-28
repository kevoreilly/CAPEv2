# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import dataclasses
import datetime
import hashlib
import os
import pathlib
import shutil
from functools import partial
from tempfile import NamedTemporaryFile
from typing import Optional

import pytest
from sqlalchemy.exc import SQLAlchemyError

from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.path_utils import path_mkdir
from lib.cuckoo.common.utils import store_temp_file
from lib.cuckoo.core import database
from lib.cuckoo.core.database import (
    TASK_BANNED,
    TASK_COMPLETED,
    TASK_PENDING,
    TASK_REPORTED,
    TASK_RUNNING,
    Guest,
    Machine,
    Sample,
    Tag,
    Task,
    _Database,
    machines_tags,
)


@dataclasses.dataclass
class StorageLayout:
    tmp_path: pathlib.Path
    storage: str
    binary_storage: str
    analyses_storage: str
    tmpdir: str


@pytest.fixture
def storage(tmp_path, request):
    storage = tmp_path / "storage"
    binaries = storage / "binaries"
    binaries.mkdir(mode=0o755, parents=True)
    analyses = storage / "analyses"
    analyses.mkdir(mode=0o755, parents=True)
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir(mode=0o755, parents=True)
    yield StorageLayout(
        tmp_path=tmp_path,
        storage=str(storage),
        binary_storage=str(binaries),
        analyses_storage=str(analyses),
        tmpdir=str(tmpdir),
    )
    shutil.rmtree(str(tmp_path))


@pytest.fixture
def temp_filename(storage: StorageLayout):
    with NamedTemporaryFile(mode="w+", delete=False, dir=storage.storage) as f:
        f.write("hehe")
    yield f.name


@pytest.fixture
def temp_pcap(temp_filename: str, storage: StorageLayout):
    pcap_header_base64 = b"1MOyoQIABAAAAAAAAAAAAAAABAABAAAA"
    pcap_bytes = base64.b64decode(pcap_header_base64)
    yield store_temp_file(pcap_bytes, "%s.pcap" % temp_filename, storage.tmpdir.encode())


@pytest.mark.usefixtures("tmp_cuckoo_root", "storage")
class TestDatabaseEngine:
    """Test database stuff."""

    URI = None

    def add_machine(self, db: _Database, **kwargs) -> Machine:
        dflt = dict(
            name="name0",
            label="label0",
            ip="1.2.3.0",
            platform="windows",
            tags="tag1,x64",
            interface="int0",
            snapshot="snap0",
            resultserver_ip="5.6.7.8",
            resultserver_port=2043,
            arch="x64",
            reserved=False,
        )
        dflt.update(kwargs)
        return db.add_machine(**dflt)

    def test_add_tasks(self, db: _Database, temp_filename: str):
        # Add task.
        with db.session.begin():
            assert db.session.query(Task).count() == 0
        with db.session.begin():
            db.add_path(temp_filename)
        with db.session.begin():
            assert db.session.query(Task).count() == 1

        # Add url.
        with db.session.begin():
            db.add_url("http://foo.bar")
        with db.session.begin():
            assert db.session.query(Task).count() == 2

    def test_error_exists(self, db: _Database):
        err_msg = "A" * 1024
        with db.session.begin():
            task_id = db.add_url("http://google.com/")
            db.add_error(err_msg, task_id)
        with db.session.begin():
            errs = db.view_errors(task_id)
            assert len(errs) == 1
            assert errs[0].message == err_msg
        with db.session.begin():
            db.add_error(err_msg, task_id)
        with db.session.begin():
            assert len(db.view_errors(task_id)) == 2

    def test_task_set_options(self, db: _Database, temp_filename: str):
        with pytest.raises(SQLAlchemyError):
            with db.session.begin():
                # Make sure options passed in as a dict are not allowed.
                db.add_path(temp_filename, options={"foo": "bar"})

        with db.session.begin():
            t1 = db.add_path(temp_filename, options="foo=bar")

        with db.session.begin():
            assert db.view_task(t1).options == "foo=bar"

    def test_task_tags_str(self, db: _Database, temp_filename: str):
        with db.session.begin():
            t1 = db.add_path(temp_filename, tags="foo,,bar")
            t2 = db.add_path(temp_filename, tags="boo,,far")

        with db.session.begin():
            t1_tag_list = [str(x.name) for x in list(db.view_task(t1).tags)]
            t2_tag_list = [str(x.name) for x in list(db.view_task(t2).tags)]

        t1_tag_list.sort()
        t2_tag_list.sort()

        assert t1_tag_list == ["bar", "foo", "x86"]
        assert t2_tag_list == ["boo", "far", "x86"]

    def test_reschedule_file(self, db: _Database, temp_filename: str, storage: StorageLayout):
        with db.session.begin():
            task_id = db.add_path(temp_filename)
        with db.session.begin():
            assert db.session.query(Task).count() == 1
            task = db.view_task(task_id)
            assert task is not None
            db.session.expunge(task)

        assert task.category == "file"

        # write a real sample to storage
        task_path = os.path.join(storage.analyses_storage, str(task.id))
        path_mkdir(task_path)
        shutil.copy(temp_filename, os.path.join(task_path, "binary"))

        with db.session.begin():
            new_task_id = db.reschedule(task_id)
        assert new_task_id is not None

        with db.session.begin():
            new_task = db.view_task(new_task_id)
        assert new_task.category == "file"

    def test_reschedule_static(self, db: _Database, temp_filename: str, storage: StorageLayout):
        with db.session.begin():
            task_ids = db.add_static(temp_filename)
        assert len(task_ids) == 1
        task_id = task_ids[0]
        with db.session.begin():
            assert db.session.query(Task).count() == 1
            task = db.view_task(task_id)
            assert task is not None
            db.session.expunge_all()
        assert task.category == "static"

        # write a real sample to storage
        static_path = os.path.join(storage.binary_storage, task.sample.sha256)
        shutil.copy(temp_filename, static_path)

        with db.session.begin():
            new_task_id = db.reschedule(task_id)
            assert new_task_id is not None
        with db.session.begin():
            new_task = db.view_task(new_task_id[0])
            assert new_task.category == "static"

    def test_reschedule_pcap(self, db: _Database, temp_pcap: str, storage: StorageLayout):
        with db.session.begin():
            task_id = db.add_pcap(temp_pcap)
        with db.session.begin():
            assert db.session.query(Task).count() == 1
            task = db.view_task(task_id)
            assert task is not None
            db.session.expunge_all()
        assert task.category == "pcap"

        # write a real sample to storage
        pcap_path = os.path.join(storage.binary_storage, task.sample.sha256)
        shutil.copy(temp_pcap, pcap_path)

        # reschedule the PCAP task
        with db.session.begin():
            new_task_id = db.reschedule(task_id)
        assert new_task_id is not None
        with db.session.begin():
            new_task = db.view_task(new_task_id)
            assert new_task.category == "pcap"

    def test_reschedule_url(self, db: _Database):
        # add a URL task
        with db.session.begin():
            task_id = db.add_url("test_reschedule_url")
        with db.session.begin():
            assert db.session.query(Task).count() == 1
            task = db.view_task(task_id)
            assert task is not None
            assert task.category == "url"

        # reschedule the URL task
        with db.session.begin():
            new_task_id = db.reschedule(task_id)
        assert new_task_id is not None
        with db.session.begin():
            new_task = db.view_task(new_task_id)
            assert new_task.category == "url"

    def test_add_machine(self, db: _Database):
        with db.session.begin():
            self.add_machine(db, name="name1", label="label1", tags="tag1 tag2,tag3")
            self.add_machine(db, name="name2", label="label2", tags="tag1 tag2", reserved=True)
        with db.session.begin():
            m1 = db.view_machine("name1")
            m2 = db.view_machine("name2")

            assert m1.to_dict() == {
                "status": None,
                "locked": False,
                "name": "name1",
                "resultserver_ip": "5.6.7.8",
                "ip": "1.2.3.0",
                "tags": ["tag1tag2", "tag3"],
                "label": "label1",
                "locked_changed_on": None,
                "platform": "windows",
                "snapshot": "snap0",
                "interface": "int0",
                "status_changed_on": None,
                "id": 1,
                "resultserver_port": "2043",
                "arch": "x64",
                "reserved": False,
            }

            assert m2.to_dict() == {
                "id": 2,
                "interface": "int0",
                "ip": "1.2.3.0",
                "label": "label2",
                "locked": False,
                "locked_changed_on": None,
                "name": "name2",
                "platform": "windows",
                "resultserver_ip": "5.6.7.8",
                "resultserver_port": "2043",
                "snapshot": "snap0",
                "status": None,
                "status_changed_on": None,
                "tags": ["tag1tag2"],
                "arch": "x64",
                "reserved": True,
            }

    @pytest.mark.parametrize(
        "reserved,requested_platform,requested_machine,is_serviceable",
        (
            (False, "windows", None, True),
            (False, "linux", None, False),
            (False, "windows", "label0", True),
            (False, "linux", "label0", False),
            (True, "windows", None, False),
            (True, "linux", None, False),
            (True, "windows", "label0", True),
            (True, "linux", "label0", False),
        ),
    )
    def test_serviceability(
        self, db: _Database, reserved: bool, requested_platform: str, requested_machine: Optional[str], is_serviceable: bool
    ):
        with db.session.begin():
            self.add_machine(db, reserved=reserved)
        task = Task()
        task.platform = requested_platform
        task.machine = requested_machine
        task.tags = [Tag("tag1")]
        # tasks matching the available machines are serviceable
        with db.session.begin():
            assert db.is_serviceable(task) is is_serviceable

    def test_clean_machines(self, db: _Database):
        """Add a couple machines and make sure that clean_machines removes them and their tags."""
        with db.session.begin():
            for i, tags in ((1, "tag1"), (2, None)):
                self.add_machine(
                    db,
                    name=f"name{i}",
                    label=f"label{i}",
                    ip=f"1.2.3.{i}",
                    tags=tags,
                )
        with db.session.begin():
            db.clean_machines()

        with db.session.begin():
            assert db.session.query(Machine).count() == 0
            assert db.session.query(Tag).count() == 1
            assert db.session.query(machines_tags).count() == 0

    def test_delete_machine(self, db: _Database):
        machines = []
        with db.session.begin():
            for i, tags in ((1, "tag1"), (2, None)):
                machines.append(f"name{i}")
                self.add_machine(
                    db,
                    name=machines[-1],
                    label=f"label{i}",
                    ip=f"1.2.3.{i}",
                    tags=tags,
                )
        with db.session.begin():
            assert db.delete_machine(machines[0])
            assert db.session.query(Machine).count() == 1
            # Attempt to delete the same machine.
            assert not db.delete_machine(machines[0])
            assert db.session.query(Machine).count() == 1
            assert db.delete_machine(machines[1])
            assert db.session.query(Machine).count() == 0

    def test_set_machine_interface(self, db: _Database):
        intf = "newintf"
        with db.session.begin():
            self.add_machine(db)
            assert db.set_machine_interface("label0", intf) is not None
            assert db.set_machine_interface("idontexist", intf) is None

        with db.session.begin():
            assert db.session.query(Machine).filter_by(label="label0").one().interface == intf

    def test_update_clock_file(self, db: _Database, temp_filename: str, monkeypatch, freezer):
        with db.session.begin():
            # This task ID doesn't exist.
            assert db.update_clock(1) is None

            task_id = db.add_path(temp_filename)
            now = datetime.datetime.utcnow()
            monkeypatch.setattr(db.cfg.cuckoo, "daydelta", 1)
            new_clock = now + datetime.timedelta(days=1)
            assert db.update_clock(task_id) == new_clock
        with db.session.begin():
            assert db.session.query(Task).one().clock == new_clock

    def test_update_clock_url(self, db: _Database, monkeypatch, freezer):
        with db.session.begin():
            task_id = db.add_url("https://www.google.com")
            now = datetime.datetime.utcnow()
            monkeypatch.setattr(database.datetime, "utcnow", lambda: now)
            # URL's are unaffected by the daydelta setting.
            monkeypatch.setattr(db.cfg.cuckoo, "daydelta", 1)
            assert db.update_clock(task_id) == now
        with db.session.begin():
            assert db.session.query(Task).one().clock == now

    def test_set_status(self, db: _Database, freezer):
        with db.session.begin():
            assert db.set_status(1, TASK_COMPLETED) is None
            task_id = db.add_url("https://www.google.com")
        with db.session.begin():
            task = db.session.query(Task).filter_by(id=task_id).one()
            assert task.started_on is None
            assert task.completed_on is None
            now = datetime.datetime.utcnow()
            freezer.move_to(now)
            db.set_status(task_id, TASK_RUNNING)
            task = db.session.query(Task).filter_by(id=task_id).one()
            assert task.status == TASK_RUNNING
            assert task.started_on == now
            assert task.completed_on is None

            new_now = now + datetime.timedelta(seconds=1)
            freezer.move_to(new_now)
            db.set_status(task_id, TASK_COMPLETED)
            task = db.session.query(Task).filter_by(id=task_id).one()
            assert task.status == TASK_COMPLETED
            assert task.started_on == now
            assert task.completed_on == new_now

    def test_set_task_vm_and_guest_start(self, db: _Database, freezer):
        with db.session.begin():
            assert db.set_task_vm_and_guest_start(1, "vmname", "vmlabel", "vmplatform", 1, "kvm") is None
            task_id = db.add_url("https://www.google.com")
            machine = self.add_machine(db)
            db.session.expunge_all()
        with db.session.begin():
            guest_id = db.set_task_vm_and_guest_start(task_id, machine.name, machine.label, machine.platform, machine.id, "KVM")
        assert guest_id is not None
        with db.session.begin():
            task = db.session.query(Task).filter_by(id=task_id).one()
            guest = db.session.query(Guest).filter_by(id=guest_id).one()
            assert task.guest == guest
            assert task.machine == "name0"
            assert task.machine_id == machine.id
            assert guest.status == "init"
            assert guest.name == "name0"
            assert guest.label == "label0"
            assert guest.manager == "KVM"
            # The started_on time is generated in the database whereas datetime.now()
            # is using the time given by freezegun when this test began.
            assert guest.started_on >= datetime.datetime.now()
            assert guest.shutdown_on is None
            assert guest.task_id == task_id

    def test_guest_stop(self, db: _Database, freezer):
        with db.session.begin():
            db.guest_stop(1)
            task_id = db.add_url("https://www.google.com")
            machine = self.add_machine(db)
            guest_id = db.set_task_vm_and_guest_start(task_id, machine.name, machine.label, machine.platform, machine.id, "KVM")
        with db.session.begin():
            new_time = datetime.datetime.now() + datetime.timedelta(minutes=1)
            freezer.move_to(new_time)
            db.guest_stop(guest_id)
        with db.session.begin():
            assert db.session.query(Guest).get(guest_id).shutdown_on == new_time

    @pytest.mark.parametrize(
        "kwargs,expected_machines",
        (
            ({"locked": True}, {"n2"}),
            ({"locked": False}, {"n1", "n4", "n5", "n6"}),
            # Make sure providing a label overrides "include_reserved"
            ({"label": "l3"}, {"n3"}),
            ({"label": "foo"}, set()),
            ({"platform": "windows"}, {"n1", "n2", "n5", "n6"}),
            ({"platform": "osx"}, set()),
            ({"tags": ["tag1"]}, {"n1", "n2", "n4", "n6"}),
            ({"tags": ["foo"]}, set()),
            ({"arch": ["x86"]}, {"n1", "n2", "n4", "n5", "n6"}),
            ({"arch": ["x64"]}, {"n1", "n2", "n4", "n5"}),
            ({"arch": ["xy"]}, set()),
            ({"os_version": ["win10"]}, {"n5"}),
            ({"os_version": ["winxp"]}, set()),
            ({"include_reserved": True}, {"n1", "n2", "n3", "n4", "n5", "n6"}),
        ),
    )
    def test_list_machines(self, db: _Database, kwargs, expected_machines):
        with db.session.begin():
            self.add_machine(db, name="n1", label="l1")
            m = self.add_machine(db, name="n2", label="l2")
            m.locked = True
            self.add_machine(db, name="n3", label="l3", reserved=True)
            self.add_machine(db, name="n4", label="l4", platform="linux")
            self.add_machine(db, name="n5", label="l5", tags="win10")
            self.add_machine(db, name="n6", label="l6", arch="x86")
        with db.session.begin():
            actual_machines = [machine.name for machine in db.list_machines(**kwargs)]
            if kwargs == {"arch": ["x86"]}:
                # This is the only parameter that causes the returned value to be in any
                # guaranteed order.
                assert actual_machines[0] == "n6"
            actual_machines_set = set(actual_machines)
            assert actual_machines_set == expected_machines

    @pytest.mark.parametrize(
        "kwargs,expected_retval",
        (
            ({"machine": "l1"}, False),
            ({"machine": "l2"}, True),
            ({"machine": "l3"}, True),
            ({"machine": "foo"}, False),
            ({"platform": "windows"}, True),
            ({"platform": "osx"}, False),
            ({"tags": "tag1"}, True),
            ({"tags": "foo"}, False),
            ({"tags": "x64"}, True),
            ({"tags": ""}, True),
            ({"tags": "arm"}, False),
            # msix requires a machine with the win10 or win11 tag.
            ({"package": "msix"}, False),
            ({"package": "foo"}, True),
        ),
    )
    def test_is_relevant_machine_available(self, db: _Database, temp_filename: str, kwargs, expected_retval):
        with db.session.begin():
            m = self.add_machine(db, name="n1", label="l1")
            m.locked = True
            self.add_machine(db, name="n2", label="l2", tags="tag1,x64")
            self.add_machine(db, name="n3", label="l3", reserved=True)

            task_id = db.add_path(temp_filename, **kwargs)
        with db.session.begin():
            task = db.session.get(Task, task_id)
            assert db.is_relevant_machine_available(task) is expected_retval
            assert (task.status == TASK_RUNNING) is expected_retval

    @pytest.mark.parametrize(
        "categories,expected_task",
        (
            (None, "t3"),
            (["url"], "t3"),
            (["file"], "t4"),
            (["other"], None),
        ),
    )
    def test_fetch_task(self, db: _Database, temp_filename, categories, expected_task):
        with db.session.begin():
            tasks = dict(
                t1=db.add_url("https://www.google.com"),
                t2=db.add_url("https://www.google.com"),
                t3=db.add_url("https://www.google.com", priority=2),
                t4=db.add_path(temp_filename),
            )
            db.set_status(tasks["t2"], TASK_RUNNING)
        with db.session.begin():
            task = db.fetch_task(categories)
            if expected_task is None:
                assert task is None
            else:
                assert task.id == tasks[expected_task]
                assert task.status == TASK_RUNNING

    def test_guest_get_status(self, db: _Database):
        with db.session.begin():
            task_id = db.add_url("https://www.google.com")
            machine = self.add_machine(db)
            db.set_task_vm_and_guest_start(task_id, machine.name, machine.label, machine.platform, machine.id, "KVM")
        with db.session.begin():
            assert db.guest_get_status(task_id + 1) is None
            assert db.guest_get_status(task_id) == "init"

    def test_guest_set_status(self, db: _Database):
        with db.session.begin():
            task_id = db.add_url("https://www.google.com")
            machine = self.add_machine(db)
            db.set_task_vm_and_guest_start(task_id, machine.name, machine.label, machine.platform, machine.id, "KVM")
        with db.session.begin():
            db.guest_set_status(task_id, "failed")
        with db.session.begin():
            assert db.guest_get_status(task_id) == "failed"

    def test_guest_remove(self, db: _Database):
        with db.session.begin():
            task_id = db.add_url("https://www.google.com")
            machine = self.add_machine(db)
            guest_id = db.set_task_vm_and_guest_start(task_id, machine.name, machine.label, machine.platform, machine.id, "KVM")
        with db.session.begin():
            db.guest_remove(guest_id)
        assert db.session.query(Guest).count() == 0

    @pytest.mark.parametrize(
        "kwargs,expected_retval",
        (
            ({"label": "l1"}, None),
            ({"label": "l2"}, {"l2"}),
            ({"label": "l3"}, {"l3"}),
            ({"label": "foo"}, CuckooOperationalError),
            ({"platform": "windows"}, {"l2", "l4"}),
            ({"platform": "osx"}, CuckooOperationalError),
            ({"tags": ["tag1"]}, {"l2", "l4"}),
            ({"tags": ["foo"]}, CuckooOperationalError),
            ({"arch": ["x64"]}, {"l2"}),
            ({"arch": ["x86"]}, {"l4"}),
            ({"arch": ["arm"]}, CuckooOperationalError),
            # msix requires a machine with the win10 or win11 tag.
            ({"os_version": ["win10"]}, {"l4"}),
            ({"os_version": ["foo"]}, CuckooOperationalError),
            ({"label": "l2", "platform": "windows"}, None),
            ({"label": "l2", "tags": ["tag1"]}, None),
        ),
    )
    def test_lock_machine(self, db: _Database, kwargs, expected_retval, freezer):
        with db.session.begin():
            m = self.add_machine(db, name="n1", label="l1")
            m.locked = True
            self.add_machine(db, name="n2", label="l2", tags="tag1,x64")
            self.add_machine(db, name="n3", label="l3", reserved=True)
            self.add_machine(db, name="n4", label="l4", tags="tag1,win10", arch="x86")
        with db.session.begin():
            if isinstance(expected_retval, type) and issubclass(expected_retval, Exception):
                with pytest.raises(expected_retval):
                    db.lock_machine(**kwargs)
            else:
                machine = db.lock_machine(**kwargs)
                if expected_retval is None:
                    assert machine is None
                else:
                    assert machine is not None
                    assert machine.label in expected_retval
                    assert machine.locked
                    assert machine.locked_changed_on == datetime.datetime.now()

    def test_unlock_machine(self, db: _Database, freezer):
        with db.session.begin():
            m1 = self.add_machine(db, name="n1", label="l1")
            m1.locked = True
            m2 = self.add_machine(db, name="n2", label="l2")
            m2.locked = True
        with db.session.begin():
            machine = db.unlock_machine("l1")
            assert machine.label == "l1"
        with db.session.begin():
            machine = db.session.query(Machine).filter_by(label="l1").one()
            assert not machine.locked
            assert machine.locked_changed_on == datetime.datetime.now()

            assert db.unlock_machine("foo") is None

    @pytest.mark.parametrize(
        "kwargs,expected_retval",
        (
            ({"label": "l1"}, 0),
            ({"label": "l2"}, 1),
            ({"label": "l3"}, 1),
            ({"label": "foo"}, 0),
            ({"platform": "windows"}, 2),
            ({"platform": "osx"}, 0),
            ({"tags": ["tag1"]}, 2),
            ({"tags": ["foo"]}, 0),
            ({"arch": ["x64"]}, 1),
            ({"arch": ["x86"]}, 2),
            ({"arch": ["arm"]}, 0),
            # msix requires a machine with the win10 or win11 tag.
            ({"os_version": ["win10"]}, 1),
            ({"os_version": ["foo"]}, 0),
            ({"include_reserved": True}, 3),
        ),
    )
    def test_count_machines_available(self, db: _Database, kwargs, expected_retval):
        with db.session.begin():
            m = self.add_machine(db, name="n1", label="l1")
            m.locked = True
            self.add_machine(db, name="n2", label="l2", tags="tag1,x64")
            self.add_machine(db, name="n3", label="l3", reserved=True)
            self.add_machine(db, name="n4", label="l4", tags="tag1,win10", arch="x86")
        with db.session.begin():
            assert db.count_machines_available(**kwargs) == expected_retval

    def test_get_available_machines(self, db: _Database):
        with db.session.begin():
            m = self.add_machine(db, name="n1", label="l1")
            m.locked = True
            self.add_machine(db, name="n2", label="l2", tags="tag1,x64")
            self.add_machine(db, name="n3", label="l3", reserved=True)
        with db.session.begin():
            assert set(m.label for m in db.get_available_machines()) == {"l2", "l3"}

    def test_set_machine_status(self, db: _Database, freezer):
        with db.session.begin():
            self.add_machine(db, name="n1", label="l1")
            self.add_machine(db, name="n2", label="l2")
        with db.session.begin():
            db.set_machine_status("l2", "running")
        with db.session.begin():
            machine = db.session.query(Machine).filter_by(label="l2").one()
            assert machine.status == "running"
            assert machine.status_changed_on == datetime.datetime.now()

            machine = db.session.query(Machine).filter_by(label="l1").one()
            assert machine.status != "running"

    @pytest.mark.parametrize(
        "kwargs,expected_count",
        (
            ({}, 3),
            ({"category": "url"}, 2),
            ({"category": "foo"}, 0),
            ({"status": "running"}, 1),
            ({"status": "foo"}, 0),
            ({"not_status": "running"}, 2),
            ({"not_status": "foo"}, 3),
            ({"status": "running", "not_status": "running"}, 0),
        ),
    )
    def test_count_matching_tasks(self, db: _Database, temp_filename, kwargs, expected_count):
        with db.session.begin():
            db.add_path(temp_filename)
            db.add_url("https://www.google.com")
            t3 = db.add_url("https://www.bing.com")
            db.set_status(t3, "running")
        with db.session.begin():
            assert db.count_matching_tasks(**kwargs) == expected_count

    def test_check_file_uniq(self, db: _Database, temp_filename, freezer):
        with db.session.begin():
            assert not db.check_file_uniq("a")
            db.add_path(temp_filename)
        with db.session.begin():
            with open(temp_filename, "rb") as fil:
                sha256 = hashlib.sha256(fil.read()).hexdigest()
            assert db.check_file_uniq(sha256)
            freezer.move_to(datetime.datetime.now() + datetime.timedelta(hours=2))
            assert not db.check_file_uniq(sha256, hours=1)

    def test_list_sample_parent(self, db: _Database, temp_filename):
        dct = dict(
            md5="md5",
            crc32="crc32",
            sha1="sha1",
            sha256="sha256",
            sha512="sha512",
            file_size=100,
            file_type="file_type",
            ssdeep="ssdeep",
            source_url="source_url",
        )
        with db.session.begin():
            with db.session.begin_nested():
                sample = Sample(**dct)
                db.session.add(sample)
            sample_id = sample.id
            task_id = db.add_path(temp_filename)
            sample2 = db.session.query(Sample).filter(Sample.id != sample.id).one()
            sample2.parent = sample_id

        with db.session.begin():
            exp_val = dict(**dct, parent=None, id=sample_id)
            assert db.list_sample_parent(task_id=task_id) == exp_val
            assert db.list_sample_parent(task_id=task_id + 1) == {}

    def test_list_tasks(self, db: _Database, temp_filename, freezer):
        with db.session.begin():
            t1 = db.add_path(temp_filename, options="minhook=1")
            t2 = db.add_url("https://2.com", tags_tasks="tag1")
            t3 = db.add_url("https://3.com", user_id=5)
        start = datetime.datetime.now()
        with db.session.begin():

            def get_ids(**kwargs):
                return [t.id for t in db.list_tasks(**kwargs)]

            assert get_ids(limit=1) == [t3]
            assert get_ids(category="url") == [t3, t2]
            assert get_ids(offset=1) == [t2, t1]
            with db.session.begin_nested() as nested:
                now = start + datetime.timedelta(minutes=1)
                freezer.move_to(now)
                db.set_status(t2, TASK_COMPLETED)
                db.session.query(Task).get(t1).added_on = start
                db.session.query(Task).get(t2).added_on = start + datetime.timedelta(seconds=1)
                db.session.query(Task).get(t3).added_on = now
                assert get_ids(status=TASK_COMPLETED) == [t2]
                assert get_ids(not_status=TASK_COMPLETED) == [t3, t1]
                assert get_ids(completed_after=start) == [t2]
                assert get_ids(order_by=(Task.completed_on, Task.id)) == [t1, t3, t2]
                assert get_ids(order_by=(Task.id)) == [t1, t2, t3]
                assert get_ids(added_before=now) == [t2, t1]
                nested.rollback()
            assert get_ids(sample_id=1) == [t1]
            assert get_ids(id_before=t3) == [t2, t1]
            assert get_ids(id_after=t2) == [t3]
            assert get_ids(options_like="minhook") == [t1]
            assert get_ids(options_not_like="minhook") == [t3, t2]
            assert get_ids(tags_tasks_like="1") == [t2]
            assert get_ids(task_ids=(t1, t2)) == [t2, t1]
            assert get_ids(task_ids=(t3 + 1,)) == []
            assert get_ids(user_id=5) == [t3]
            assert get_ids(user_id=0) == [t2, t1]

    def test_minmax_tasks(self, db: _Database, freezer):
        with db.session.begin():
            assert db.minmax_tasks() == (0, 0)

        start_time = datetime.datetime.now()
        with db.session.begin():
            t1 = db.add_url("https://1.com")
            t2 = db.add_url("https://2.com")
            t3 = db.add_url("https://3.com")
            t4 = db.add_url("https://4.com")
            _t5 = db.add_url("https://5.com")
            t2_started = start_time
            freezer.move_to(t2_started)
            db.set_status(t2, TASK_RUNNING)
            freezer.move_to(start_time + datetime.timedelta(minutes=1))
            db.set_status(t1, TASK_RUNNING)
            freezer.move_to(start_time + datetime.timedelta(minutes=2))
            db.set_status(t3, TASK_RUNNING)
            freezer.move_to(start_time + datetime.timedelta(minutes=3))
            db.set_status(t4, TASK_RUNNING)
            # t5 has not started

            freezer.move_to(start_time + datetime.timedelta(minutes=4))
            db.set_status(t1, TASK_COMPLETED)
            # t2 is still running
            freezer.move_to(start_time + datetime.timedelta(minutes=5))
            db.set_status(t4, TASK_COMPLETED)
            t3_completed = start_time + datetime.timedelta(minutes=6)
            freezer.move_to(t3_completed)
            db.set_status(t3, TASK_COMPLETED)
        with db.session.begin():
            assert db.minmax_tasks() == (int(t2_started.timestamp()), int(t3_completed.timestamp()))

    def test_get_tlp_tasks(self, db: _Database):
        with db.session.begin():
            db.add_url("https://1.com")
        with db.session.begin():
            assert db.get_tlp_tasks() == []
        with db.session.begin():
            t2 = db.add_url("https://2.com", tlp="true")
        with db.session.begin():
            assert db.get_tlp_tasks() == [t2]

    def test_get_file_types(self, db: _Database, temp_filename):
        with db.session.begin():
            assert db.get_file_types() == []
        with db.session.begin():
            for i in range(2):
                db.session.add(
                    Sample(
                        md5=f"md5_{i}",
                        sha1=f"sha1_{i}",
                        crc32=f"crc32_{i}",
                        sha256=f"sha256_{i}",
                        sha512=f"sha512_{i}",
                        file_size=100 + i,
                        file_type=f"file_type_{i}",
                    )
                )
        with db.session.begin():
            assert db.get_file_types() == ["file_type_0", "file_type_1"]

    def test_get_tasks_status_count(self, db: _Database):
        with db.session.begin():
            assert db.get_tasks_status_count() == {}
        with db.session.begin():
            _t1 = db.add_url("https://1.com")
            t2 = db.add_url("https://2.com")
            t3 = db.add_url("https://3.com")
            db.set_status(t2, TASK_RUNNING)
            db.set_status(t3, TASK_RUNNING)
        with db.session.begin():
            assert db.get_tasks_status_count() == {
                TASK_PENDING: 1,
                TASK_RUNNING: 2,
            }

    def test_count_tasks(self, db: _Database):
        with db.session.begin():
            assert db.count_tasks() == 0
        with db.session.begin():
            _t1 = db.add_url("https://1.com")
            t2 = db.add_url("https://2.com")
            t3 = db.add_url("https://3.com")
            db.set_status(t2, TASK_RUNNING)
            db.set_status(t3, TASK_RUNNING)
        with db.session.begin():
            assert db.count_tasks() == 3
            assert db.count_tasks(status=TASK_RUNNING) == 2
            assert db.count_tasks(status=TASK_COMPLETED) == 0

    def test_delete_task(self, db: _Database, temp_filename):
        with db.session.begin():
            t1 = db.add_url("https://1.com")
            t2 = db.add_path(temp_filename, tags="x86")
        with db.session.begin():
            db.delete_task(t2)
        with db.session.begin():
            tasks = db.session.query(Task).all()
            assert len(tasks) == 1
            assert tasks[0].id == t1
            assert not db.delete_task(t2)

    def test_delete_tasks(self, db: _Database, temp_filename):
        with db.session.begin():
            t1 = db.add_url("https://1.com")
            t2 = db.add_path(temp_filename, tags="x86")
            t3 = db.add_url("https://3.com")
        with db.session.begin():
            assert db.delete_tasks([])
            assert db.delete_tasks([t1, t2, t3 + 1])
            tasks = db.session.query(Task).all()
            assert len(tasks) == 1
            assert tasks[0].id == t3
            assert db.delete_tasks([t1, t2])
            tasks = db.session.query(Task).all()
            assert len(tasks) == 1
            assert tasks[0].id == t3

    def test_view_sample(self, db: _Database):
        with db.session.begin():
            samples = []
            for i in range(2):
                samples.append(
                    Sample(
                        md5=f"md5_{i}",
                        sha1=f"sha1_{i}",
                        crc32=f"crc32_{i}",
                        sha256=f"sha256_{i}",
                        sha512=f"sha512_{i}",
                        file_size=100 + i,
                        file_type=f"file_type_{i}",
                    )
                )
                with db.session.begin_nested():
                    db.session.add(samples[-1])
                db.session.expunge(samples[-1])
        with db.session.begin():
            assert db.view_sample(samples[-1].id).to_dict() == samples[-1].to_dict()
            assert db.view_sample(samples[-1].id + 1) is None

    def test_find_sample(self, db: _Database, temp_filename):
        with db.session.begin():
            samples = []
            parent_id = None
            for i in range(2):
                sample = Sample(
                    md5=f"md5_{i}",
                    sha1=f"sha1_{i}",
                    crc32=f"crc32_{i}",
                    sha256=f"sha256_{i}",
                    sha512=f"sha512_{i}",
                    file_size=100 + i,
                    file_type=f"file_type_{i}",
                    parent=parent_id,
                )
                with db.session.begin_nested():
                    db.session.add(sample)
                parent_id = sample.id
                samples.append(sample.id)
            t1 = db.add_path(temp_filename)
            with open(temp_filename, "rb") as fil:
                sha256 = hashlib.sha256(fil.read()).hexdigest()
            task_sample = db.session.query(Sample).filter_by(sha256=sha256).one().id
        with db.session.begin():
            assert db.find_sample() is False
            assert db.find_sample(md5="md5_1").id == samples[1]
            assert db.find_sample(sha1="sha1_1").id == samples[1]
            assert db.find_sample(sha256="sha256_0").id == samples[0]
            assert [s.id for s in db.find_sample(parent=samples[0])] == samples[1:]
            assert [s.id for s in db.find_sample(parent=samples[1])] == []
            # When a task_id is passed, find_sample returns Task objects instead of Sample objects.
            assert [t.sample.id for t in db.find_sample(task_id=t1)] == [task_sample]
            assert [s.id for s in db.find_sample(sample_id=samples[1])] == [samples[1]]

    def test_sample_still_used(self, db: _Database, temp_filename):
        with db.session.begin():
            t1 = db.add_path(temp_filename)
        with open(temp_filename, "rb") as fil:
            sha256 = hashlib.sha256(fil.read()).hexdigest()
        with db.session.begin():
            # No other tasks are associated with this sample.
            assert not db.sample_still_used(sha256, t1)
        with db.session.begin():
            # Add another task for the sample.
            t2 = db.add_path(temp_filename)
        with db.session.begin():
            # So now it IS still being used.
            assert db.sample_still_used(sha256, t1)
        with db.session.begin():
            # Mark the second task as completed...
            db.set_status(t2, TASK_COMPLETED)
        with db.session.begin():
            # So it is no longer "used".
            assert not db.sample_still_used(sha256, t1)

    def test_count_samples(self, db: _Database, temp_filename):
        with db.session.begin():
            assert db.count_samples() == 0
            db.add_path(temp_filename)
        with db.session.begin():
            assert db.count_samples() == 1

    def test_view_machine_by_label(self, db: _Database):
        with db.session.begin():
            m0 = self.add_machine(db, name="name0", label="label0")
            self.add_machine(db, name="name1", label="label1")
            db.session.refresh(m0)
            db.session.expunge_all()
        with db.session.begin():
            assert db.view_machine_by_label("foo") is None
            m0_dict = db.session.query(Machine).get(m0.id).to_dict()
            assert db.view_machine_by_label("label0").to_dict() == m0_dict

    def test_get_source_url(self, db: _Database, temp_filename):
        with db.session.begin():
            assert db.get_source_url() is False
            assert db.get_source_url(1) is None
            db.add_path(temp_filename)
            with open(temp_filename, "a") as fil:
                fil.write("a")
            db.add_path(temp_filename)
            url = "https://badguys.com"
            db.session.query(Sample).get(1).source_url = url
        with db.session.begin():
            assert db.get_source_url(1) == url
            assert db.get_source_url(2) is None

    def test_ban_user_tasks(self, db: _Database):
        with db.session.begin():
            t1 = db.add_url("https://1.com", user_id=0)
            t2 = db.add_url("https://2.com", user_id=1)
            t3 = db.add_url("https://3.com", user_id=1)
            t4 = db.add_url("https://3.com", user_id=1)
            db.set_status(t4, TASK_COMPLETED)
        with db.session.begin():
            db.ban_user_tasks(1)
            assert db.session.query(Task).get(t1).status == TASK_PENDING
            assert db.session.query(Task).get(t2).status == TASK_BANNED
            assert db.session.query(Task).get(t3).status == TASK_BANNED
            assert db.session.query(Task).get(t4).status == TASK_COMPLETED

    def test_tasks_reprocess(self, db: _Database):
        with db.session.begin():
            err, _msg, old_status = db.tasks_reprocess(1)
            assert err is True
            assert old_status == ""
            t1 = db.add_url("https://1.com")
        with db.session.begin():
            err, _msg, old_status = db.tasks_reprocess(t1)
            assert err is True
            assert old_status == TASK_PENDING
            db.set_status(t1, TASK_REPORTED)
        with db.session.begin():
            err, _msg, old_status = db.tasks_reprocess(t1)
            assert err is False
            assert old_status == TASK_REPORTED
            assert db.session.query(Task).get(t1).status == TASK_COMPLETED

    @pytest.mark.parametrize(
        "task_instructions,machine_instructions,expected_results",
        # @param task_instructions : list of tasks to be created, each tuple represent the tag to associate to tasks and the number of such tasks to create
        # @param machine_instructions : list of machines to be created, each collections represent the parameters to associate to machines and the number of such machines to create
        # @param expected_results : dictionary of expected tasks to be mapped to machines numbered by their tags
        (
            # No tasks, no machines
            (
                [],
                [],
                {},
            ),
            # Assign 10 tasks with the same tag to 10 available machines with that tag
            (
                [("tag1", 10)],
                [("windows", "x64", "tag1", 10)],
                {"tag1": 10},
            ),
            # Assign 10 tasks (8 with one tag, 2 with another) to 8 available machines with that tag and 2 available machines with the other tag
            (
                [("tag1", 8), ("tag2", 2)],
                [("windows", "x64", "tag1,", 8), ("windows", "x86", "tag2,", 2)],
                {"tag1": 8, "tag2": 2},
            ),
            # Assign 43 tasks total containing a variety of tags to 40/80 available machines with the first tag, 2/2 available machines with the second tag and 1/2 available machines with the third tag
            (
                [("tag1", 40), ("tag2", 2), ("tag3", 1)],
                [("windows", "x64", "tag1", 80), ("windows", "x86", "tag2", 2), ("linux", "x64", "tag3", 2)],
                {"tag1": 40, "tag2": 2, "tag3": 1},
            ),
        ),
    )
    def test_map_tasks_to_available_machines(
        self, task_instructions, machine_instructions, expected_results, db: _Database, request
    ):
        tasks = []
        machines = []

        # Parsing machine instructions
        with db.session.begin():
            for machine_instruction in machine_instructions:
                platform, archs, tags, num_of_machines = machine_instruction
                for i in range(num_of_machines):
                    machine_name = str(platform) + str(archs) + str(i)
                    db.add_machine(
                        name=machine_name,
                        label=machine_name,
                        ip="1.2.3.4",
                        platform=platform,
                        tags=tags,
                        interface="int0",
                        snapshot="snap0",
                        resultserver_ip="5.6.7.8",
                        resultserver_port=2043,
                        arch=archs,
                        reserved=False,
                    )
                    machines.append((machine_name, tags))
            for machine, machine_tag in machines:
                db.set_machine_status(machine, "running")
            # Parsing tasks instructions
            for task_instruction in task_instructions:
                tags, num_of_tasks = task_instruction
                for i in range(num_of_tasks):
                    task_id = "Sample_%s_%s" % (tags, i)
                    with open(task_id, "w") as f:
                        f.write(task_id)
                    request.addfinalizer(partial(os.remove, task_id))
                    task = db.add_path(file_path=task_id, tags=tags)
                    task = db.view_task(task)
                    tasks.append(task)
            db.session.expunge_all()

        # Parse the expected results
        total_task_to_be_assigned = 0
        total_task_to_be_assigned = sum(expected_results.values())

        total_task_assigned = 0
        results = []
        for tag in expected_results.keys():
            results.append([tag, 0])
        with db.session.begin():
            relevant_tasks = db.map_tasks_to_available_machines(tasks)
            db.session.expunge_all()
        for task in relevant_tasks:
            tags = [tag.name for tag in task.tags]
            for result in results:
                if result[0] == tags[0]:
                    result[1] += 1
                    break
        total_task_assigned += len(relevant_tasks)

        # Test results
        assert total_task_assigned == total_task_to_be_assigned
        for tag in expected_results.keys():
            for result in results:
                if tag == result[0]:
                    assert expected_results[tag] == result[1]

    @pytest.mark.parametrize(
        "task,machines,expected_result",
        # @param task : dictionary describing the task to be created
        # @param machines : list of machines to be created
        # @param expected_result : expected_result of the function (number of machines after being filtered)
        (
            # No filter and all machines are returned
            (
                {
                    "label": "task0",
                    "machine": None,
                    "platform": None,
                    "tags": None,
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                ],
                2,
            ),
            # Filtering by label only
            (
                {
                    "label": "task1",
                    "machine": "machine1",
                    "platform": None,
                    "tags": None,
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                ],
                1,
            ),
            # Filtering by label only
            (
                {
                    "label": "task2",
                    "machine": "machine1",
                    "platform": None,
                    "tags": None,
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine2", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine3", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag2"},
                ],
                0,
            ),
            # Filtering by platform only
            (
                {
                    "label": "task3",
                    "machine": None,
                    "platform": "windows",
                    "tags": None,
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag2"},
                ],
                2,
            ),
            # Filtering by platform only
            (
                {
                    "label": "task4",
                    "machine": None,
                    "platform": "windows",
                    "tags": None,
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag2"},
                ],
                0,
            ),
            # Filtering by tags only
            (
                {
                    "label": "task5",
                    "machine": None,
                    "platform": None,
                    "tags": "tag1",
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag1"},
                ],
                2,
            ),
            # Filtering by tags only
            (
                {
                    "label": "task6",
                    "machine": None,
                    "platform": None,
                    "tags": "tag1",
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag2"},
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag2"},
                ],
                0,
            ),
            # Filtering by archs only
            (
                {
                    "label": "task7",
                    "machine": None,
                    "platform": None,
                    "tags": "tag1,x64",
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag1"},
                ],
                2,
            ),
            # Filtering by archs only
            (
                {
                    "label": "task8",
                    "machine": None,
                    "platform": None,
                    "tags": "tag1,x64",
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "windows", "arch": "x86", "tags": "tag2"},
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x86", "tags": "tag2"},
                ],
                0,
            ),
            # Filtering by os_version only
            (
                {
                    "label": "task9",
                    "machine": None,
                    "platform": None,
                    "tags": None,
                    "os_version": ["win10"],
                    "include_reserved": False,
                },
                [
                    {
                        "label": "machine1",
                        "reserved": False,
                        "platform": "windows",
                        "arch": "x64",
                        "tags": "tag1,win10",
                    },
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag1"},
                ],
                1,
            ),
            # Filtering by os_version only
            (
                {
                    "label": "task10",
                    "machine": None,
                    "platform": None,
                    "tags": None,
                    "os_version": ["win10"],
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag1"},
                ],
                0,
            ),
            # Filtering including the reserved machines
            (
                {
                    "label": "task11",
                    "machine": None,
                    "platform": "windows",
                    "tags": "tag1",
                    "os_version": None,
                    "include_reserved": True,
                },
                [
                    {"label": "machine1", "reserved": True, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                ],
                2,
            ),
            # Filtering excluding the reserved machines
            (
                {
                    "label": "task12",
                    "machine": None,
                    "platform": "windows",
                    "tags": "tag1",
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": True, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag1"},
                ],
                0,
            ),
            # Filtering by tags and os_version
            (
                {
                    "label": "task13",
                    "machine": None,
                    "platform": None,
                    "tags": "tag1",
                    "os_version": ["win10"],
                    "include_reserved": False,
                },
                [
                    {
                        "label": "machine1",
                        "reserved": False,
                        "platform": "windows",
                        "arch": "x64",
                        "tags": "tag1,win10",
                    },
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag1"},
                ],
                1,
            ),
            # Filtering by tags and os_version
            (
                {
                    "label": "task14",
                    "machine": None,
                    "platform": None,
                    "tags": "tag1",
                    "os_version": ["win10"],
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag1"},
                ],
                0,
            ),
            # Filtering by platform and tags
            (
                {
                    "label": "task15",
                    "machine": None,
                    "platform": "windows",
                    "tags": "tag1",
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag2"},
                ],
                1,
            ),
            # Filtering by platform and tags
            (
                {
                    "label": "task16",
                    "machine": None,
                    "platform": "windows",
                    "tags": "tag1",
                    "os_version": None,
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag2"},
                ],
                0,
            ),
            # Filtering by platform,tags and os_version
            (
                {
                    "label": "task17",
                    "machine": None,
                    "platform": "windows",
                    "tags": "tag1",
                    "os_version": ["win10"],
                    "include_reserved": False,
                },
                [
                    {
                        "label": "machine1",
                        "reserved": False,
                        "platform": "windows",
                        "arch": "x64",
                        "tags": "tag1,win10",
                    },
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag1"},
                ],
                1,
            ),
            # Filtering by platform,tags and os_version
            (
                {
                    "label": "task18",
                    "machine": None,
                    "platform": "windows",
                    "tags": "tag1",
                    "os_version": ["win10"],
                    "include_reserved": False,
                },
                [
                    {"label": "machine1", "reserved": False, "platform": "windows", "arch": "x64", "tags": "tag1"},
                    {"label": "machine2", "reserved": False, "platform": "linux", "arch": "x64", "tags": "tag1"},
                ],
                0,
            ),
            # Filtering by platform,tags and os_version
            (
                {
                    "label": "task19",
                    "machine": None,
                    "platform": "windows",
                    "tags": "tag1",
                    "os_version": ["win10"],
                    "include_reserved": False,
                },
                [],
                0,
            ),
        ),
    )
    def test_filter_machines_to_task(self, task, machines, expected_result, db: _Database):
        with db.session.begin():
            for machine in machines:
                machine_name = (
                    str(machine["label"]) + str(machine["platform"]) + str(machine["arch"]) + str(task["label"].replace("task", ""))
                )
                db.add_machine(
                    name=machine_name,
                    label=machine["label"],
                    ip="1.2.3.4",
                    platform=machine["platform"],
                    tags=machine["tags"],
                    interface="int0",
                    snapshot="snap0",
                    resultserver_ip="5.6.7.8",
                    resultserver_port=2043,
                    arch=machine["arch"],
                    reserved=machine["reserved"],
                )
        if task["tags"] is not None:
            task_archs = [tag for tag in task["tags"].split(",") if tag in ("x86", "x64")]
            task_tags = [tag for tag in task["tags"].split(",") if tag not in task_archs]
        else:
            task_archs = None
            task_tags = None
        with db.session.begin():
            created_machines = db.session.query(Machine)
            output_machines = db.filter_machines_to_task(
                machines=created_machines,
                label=task["machine"],
                platform=task["platform"],
                tags=task_tags,
                archs=task_archs,
                os_version=task["os_version"],
                include_reserved=task["include_reserved"],
            )
            if isinstance(output_machines, list):
                assert len(output_machines) == expected_result
            else:
                assert output_machines.count() == expected_result

    @pytest.mark.parametrize(
        "task,expected_result",
        # @param task : dictionary describing the task to be validated
        # @param expected_result : expected_result of the function tested
        (
            # No parameters
            ({"label": None, "platform": None, "tags": None}, True),
            # Only label
            ({"label": "task1", "platform": None, "tags": None}, True),
            # Only platform
            ({"label": None, "platform": "windows", "tags": None}, True),
            # Only tags
            ({"label": None, "platform": None, "tags": "tag1"}, True),
            # Label and platform
            ({"label": "task1", "platform": "windows", "tags": None}, False),
            # Label and tags
            ({"label": "task1", "platform": None, "tags": "tag1"}, False),
            # Platform and tags
            ({"label": None, "platform": "windows", "tags": "tag1"}, True),
            # Label, Platform and tags
            ({"label": "task1", "platform": "windows", "tags": "tag1"}, False),
        ),
    )
    def test_validate_task_parameters(self, task, expected_result, db: _Database):
        assert db.validate_task_parameters(label=task["label"], platform=task["platform"], tags=task["tags"]) == expected_result
