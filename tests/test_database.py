# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import os
import shutil
from tempfile import NamedTemporaryFile

from lib.cuckoo.common.path_utils import path_cwd, path_delete, path_mkdir
from lib.cuckoo.common.utils import store_temp_file
from lib.cuckoo.core.database import Database, Tag, Task


class TestDatabaseEngine:
    """Test database stuff."""

    URI = None

    def setup_method(self):
        with NamedTemporaryFile(mode="w+", delete=False) as f:
            f.write("hehe")
        self.temp_filename = f.name
        pcap_header_base64 = b"1MOyoQIABAAAAAAAAAAAAAAABAABAAAA"
        pcap_bytes = base64.b64decode(pcap_header_base64)
        self.temp_pcap = store_temp_file(pcap_bytes, "%s.pcap" % f.name)
        self.d = Database(dsn="sqlite://")
        # self.d.connect(dsn=self.URI)
        self.session = self.d.Session()
        self.binary_storage = os.path.join(path_cwd(), "storage/binaries")
        path_mkdir(self.binary_storage)

    def teardown_method(self):
        del self.d
        path_delete(self.temp_filename)
        shutil.rmtree(self.binary_storage)

    def add_url(self, url, priority=1, status="pending"):
        task_id = self.d.add_url(url, priority=priority)
        self.d.set_status(task_id, status)
        return task_id

    def test_add_tasks(self):

        # Add task.
        count = self.session.query(Task).count()
        self.d.add_path(self.temp_filename)
        assert self.session.query(Task).count() == count + 1

        # Add url.
        self.d.add_url("http://foo.bar")
        assert self.session.query(Task).count() == count + 2

    def test_error_exists(self):
        task_id = self.add_url("http://google.com/")
        self.d.add_error("A" * 1024, task_id)
        assert len(self.d.view_errors(task_id)) == 1
        self.d.add_error("A" * 1024, task_id)
        assert len(self.d.view_errors(task_id)) == 2

    def test_long_error(self):
        self.add_url("http://google.com/")
        self.d.add_error("A" * 1024, 1)
        err = self.d.view_errors(1)
        assert err and len(err[0].message) == 1024

    def test_task_set_options(self):
        assert self.d.add_path(self.temp_filename, options={"foo": "bar"}) is None
        t1 = self.d.add_path(self.temp_filename, options="foo=bar")
        assert self.d.view_task(t1).options == "foo=bar"

    def test_task_tags_str(self):
        task = self.d.add_path(self.temp_filename, tags="foo,,bar")
        tag_list = list(self.d.view_task(task).tags)
        assert [str(x.name) for x in tag_list].sort() == ["foo", "bar"].sort()

    def test_reschedule_file(self):
        count = self.session.query(Task).count()
        task_id = self.d.add_path(self.temp_filename)
        assert self.session.query(Task).count() == count + 1
        task = self.d.view_task(task_id)
        assert task is not None
        assert task.category == "file"

        # write a real sample to storage
        sample_path = os.path.join(self.binary_storage, task.sample.sha256)
        shutil.copy(self.temp_filename, sample_path)

        new_task_id = self.d.reschedule(task_id)
        assert new_task_id is not None
        new_task = self.d.view_task(new_task_id)
        assert new_task.category == "file"

    def test_reschedule_static(self):
        count = self.session.query(Task).count()
        task_id = self.d.add_static(self.temp_filename)
        assert self.session.query(Task).count() == count + 1
        task = self.d.view_task(task_id)
        assert task is not None
        assert task.category == "static"

        # write a real sample to storage
        static_path = os.path.join(self.binary_storage, task.sample.sha256)
        shutil.copy(self.temp_filename, static_path)

        new_task_id = self.d.reschedule(task_id)
        assert new_task_id is not None
        new_task = self.d.view_task(new_task_id)
        assert new_task.category == "static"

    def test_reschedule_pcap(self):
        count = self.session.query(Task).count()
        task_id = self.d.add_pcap(self.temp_pcap)
        assert self.session.query(Task).count() == count + 1
        task = self.d.view_task(task_id)
        assert task is not None
        assert task.category == "pcap"

        # write a real sample to storage
        pcap_path = os.path.join(self.binary_storage, task.sample.sha256)
        shutil.copy(self.temp_pcap, pcap_path)

        # reschedule the PCAP task
        new_task_id = self.d.reschedule(task_id)
        assert new_task_id is not None
        new_task = self.d.view_task(new_task_id)
        assert new_task.category == "pcap"

    def test_reschedule_url(self):
        # add a URL task
        count = self.session.query(Task).count()
        task_id = self.d.add_url("test_reschedule_url")
        assert self.session.query(Task).count() == count + 1
        task = self.d.view_task(task_id)
        assert task is not None
        assert task.category == "url"

        # reschedule the URL task
        new_task_id = self.d.reschedule(task_id)
        assert new_task_id is not None
        new_task = self.d.view_task(new_task_id)
        assert new_task.category == "url"

    def test_add_machine(self):
        self.d.add_machine(
            name="name1",
            label="label",
            ip="1.2.3.4",
            platform="windows",
            tags="tag1 tag2",
            interface="int0",
            snapshot="snap0",
            resultserver_ip="5.6.7.8",
            resultserver_port=2043,
            arch="x64",
        )
        self.d.add_machine(
            name="name2",
            label="label",
            ip="1.2.3.4",
            platform="windows",
            tags="tag1 tag2",
            interface="int0",
            snapshot="snap0",
            resultserver_ip="5.6.7.8",
            resultserver_port=2043,
            arch="x64",
        )
        m1 = self.d.view_machine("name1")
        m2 = self.d.view_machine("name2")

        assert m1.to_dict() == {
            "status": None,
            "locked": False,
            "name": "name1",
            "resultserver_ip": "5.6.7.8",
            "ip": "1.2.3.4",
            "tags": ["tag1tag2"],
            "label": "label",
            "locked_changed_on": None,
            "platform": "windows",
            "snapshot": "snap0",
            "interface": "int0",
            "status_changed_on": None,
            "id": 1,
            "resultserver_port": "2043",
            "arch": "x64",
        }

        assert m2.to_dict() == {
            "id": 2,
            "interface": "int0",
            "ip": "1.2.3.4",
            "label": "label",
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
        }

    def test_is_serviceable(self):
        self.d.add_machine(
            name="win10-x64-1",
            label="label",
            ip="1.2.3.4",
            platform="windows",
            tags="tag1",
            interface="int0",
            snapshot="snap0",
            resultserver_ip="5.6.7.8",
            resultserver_port=2043,
            arch="x64",
        )
        task = Task()
        task.platform = "windows"
        task.tags = [Tag("tag1")]
        # tasks matching the available machines are serviceable
        assert self.d.is_serviceable(task)

    def test_is_not_serviceable(self):
        self.d.add_machine(
            name="win10-x64-1",
            label="label",
            ip="1.2.3.4",
            platform="windows",
            tags="tag1",
            interface="int0",
            snapshot="snap0",
            resultserver_ip="5.6.7.8",
            resultserver_port=2043,
            arch="x64",
        )
        task = Task()
        task.platform = "linux"
        task.tags = [Tag("tag1")]
        # tasks not matching the available machines aren't serviceable
        assert not self.d.is_serviceable(task)
