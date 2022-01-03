# Copyright (C) 2016-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
from tempfile import NamedTemporaryFile

from lib.cuckoo.core.database import Database, Task


class TestDatabaseEngine(object):
    """Test database stuff."""

    URI = None

    def setup_method(self):
        with NamedTemporaryFile(mode="w+", delete=False) as f:
            f.write("hehe")
        self.temp = f.name
        self.d = Database(dsn="sqlite://")
        # self.d.connect(dsn=self.URI)
        self.session = self.d.Session()

    def teardown_method(self):
        del self.d
        os.unlink(self.temp)

    def add_url(self, url, priority=1, status="pending"):
        task_id = self.d.add_url(url, priority=priority)
        self.d.set_status(task_id, status)
        return task_id

    def test_add_tasks(self):

        # Add task.
        count = self.session.query(Task).count()
        self.d.add_path(self.temp)
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
        assert self.d.add_path(self.temp, options={"foo": "bar"}) is None
        t1 = self.d.add_path(self.temp, options="foo=bar")
        assert self.d.view_task(t1).options == "foo=bar"

    def test_task_tags_str(self):
        task = self.d.add_path(self.temp, tags="foo,,bar")
        tag_list = list(self.d.view_task(task).tags)
        assert [str(x.name) for x in tag_list].sort() == ["foo", "bar"].sort()

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
