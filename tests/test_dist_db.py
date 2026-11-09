# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
from unittest.mock import MagicMock

import pytest

from lib.cuckoo.common.dist_db import Machine, Node, StringList, Task

# utils.dist hard-requires fastapi at import time; stub it when the optional dependency is absent.
if "fastapi" not in sys.modules:
    try:
        import fastapi  # noqa: F401
    except ImportError:
        _mock_fastapi = MagicMock()
        sys.modules["fastapi"] = _mock_fastapi
        sys.modules["fastapi.security"] = _mock_fastapi.security


def test_node():
    node = Node()
    need_set = set(["id", "name", "url", "enabled", "apikey", "last_check", "machines"])
    have_set = set(dir(node))
    assert need_set & have_set == need_set


def test_stringlist():
    string_list = StringList()

    assert string_list.process_bind_param(["foo", "bar"], "madeupdialect") == "foo, bar"

    assert string_list.process_result_value("foo, bar", "madeupdialect") == ["foo", "bar"]


def test_machine():
    machine = Machine()
    assert machine.__tablename__ == "machine"
    need_set = set(["id", "name", "platform", "tags", "node_id"])
    have_set = set(dir(machine))
    assert need_set & have_set == need_set


def test_task():
    task = Task(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
    need_set = set(
        [
            "path",
            "category",
            "package",
            "timeout",
            "priority",
            "options",
            "machine",
            "platform",
            "tags",
            "custom",
            "memory",
            "clock",
            "enforce_timeout",
            "main_task_id",
            "retrieved",
            "route",
        ]
    )
    have_set = set(dir(task))
    assert need_set & have_set == need_set


def test_cli_admin_commands():
    from unittest.mock import MagicMock, patch
    from utils.dist import show_status_cli, list_nodes_cli, register_node_cli, modify_node_cli

    # Test show_status_cli
    with patch("utils.dist.dist_transaction") as mock_sess:
        mock_db = MagicMock()
        mock_sess.return_value.__enter__.return_value = mock_db
        mock_db.execute.return_value.first.return_value = MagicMock(processing=1, processed=2, pending=3)

        with patch("builtins.print") as mock_print:
            show_status_cli()
            mock_print.assert_any_call("Processing tasks : 1")

    # Test list_nodes_cli
    with patch("utils.dist.dist_transaction") as mock_sess:
        mock_db = MagicMock()
        mock_sess.return_value.__enter__.return_value = mock_db
        mock_node = MagicMock()
        mock_node.name = "master"
        mock_node.enabled = True
        mock_node.url = "http://localhost:8000"

        mock_machine = MagicMock()
        mock_machine.name = "vm1"
        mock_machine.platform = "windows"
        mock_machine.tags = ""
        mock_node.machines = [mock_machine]
        mock_db.scalars.return_value.all.return_value = [mock_node]

        with patch("builtins.print") as mock_print:
            list_nodes_cli()
            assert any("master" in str(args[0]) for args, _ in mock_print.call_args_list)

    # Test register_node_cli
    with patch("utils.dist.dist_transaction") as mock_sess:
        mock_db = MagicMock()
        mock_sess.return_value.__enter__.return_value = mock_db
        mock_db.scalar.return_value = None  # Node doesn't exist

        with (
            patch("utils.dist.node_list_machines", return_value=[]),
            patch("utils.dist.node_list_exitnodes", return_value=[]),
            patch("builtins.print") as mock_print,
        ):
            register_node_cli("worker", "http://worker", "apikey", True)
            mock_print.assert_any_call("Successfully registered node 'worker' with 0 machines.")

    # Test modify_node_cli
    with patch("utils.dist.dist_transaction") as mock_sess:
        mock_db = MagicMock()
        mock_sess.return_value.__enter__.return_value = mock_db
        mock_node = MagicMock()
        mock_db.scalar.return_value = mock_node

        with patch("builtins.print") as mock_print:
            modify_node_cli("worker", enabled=False)
            assert mock_node.enabled is False
            mock_print.assert_any_call("Successfully modified node 'worker'.")


def test_node_submit_task_error_logging(caplog):
    import logging
    from unittest.mock import MagicMock, patch
    from utils.dist import node_submit_task

    # Setup mock node
    mock_node = MagicMock()
    mock_node.id = 42
    mock_node.name = "worker1"
    mock_node.url = "http://worker1.local/"
    mock_node.apikey = "test_key"

    # Setup mock task
    mock_task = MagicMock()
    mock_task.id = 16410102
    mock_task.main_task_id = 3330442
    mock_task.category = "url"
    mock_task.path = "http://malicious.url"
    mock_task.options = {}
    mock_task.tags = ""

    # Setup mock DB session
    mock_db = MagicMock()
    mock_db.get.side_effect = lambda model, _id: mock_node if model.__name__ == "Node" else mock_task

    # Mock response from requests.post
    mock_response = MagicMock()
    mock_response.status_code = 503
    mock_response.text = "Service Unavailable"
    # To simulate bool(r) is False (requests' Response behavior)
    mock_response.__bool__.return_value = False

    with (
        patch("utils.dist.dist_transaction") as mock_tx,
        patch("utils.dist.http_session.post", return_value=mock_response) as mock_post,
    ):
        mock_tx.return_value.__enter__.return_value = mock_db
        with caplog.at_level(logging.INFO):
            result = node_submit_task(task_id=16410102, node_id=42, main_task_id=3330442)

            assert result is False
            mock_post.assert_called_once()
            assert any(
                "Node: 42 - Task submit to worker failed (CAPE ID: 3330442, Task ID: 16410102): 503 - Service Unavailable"
                in record.message
                for record in caplog.records
            )


def test_node_submit_task_includes_parent_sample_in_attributes(tmp_path):
    import json
    from unittest.mock import MagicMock, patch
    from utils.dist import node_submit_task

    sample_file = tmp_path / "child.bin"
    sample_file.write_bytes(b"MZ" + b"\x00" * 30)

    mock_node = MagicMock()
    mock_node.id = 7
    mock_node.name = "worker1"
    mock_node.url = "http://worker1.local/"
    mock_node.apikey = "test_key"

    mock_task = MagicMock()
    mock_task.id = 100
    mock_task.main_task_id = 500
    mock_task.category = "file"
    mock_task.path = str(sample_file)
    mock_task.package = ""
    mock_task.timeout = 120
    mock_task.priority = 1
    mock_task.options = ""
    mock_task.machine = ""
    mock_task.platform = "windows"
    mock_task.tags = ""
    mock_task.custom = ""
    mock_task.clock = None
    mock_task.memory = False
    mock_task.enforce_timeout = False
    mock_task.route = None
    mock_task.tlp = None

    mock_db = MagicMock()
    mock_db.get.side_effect = lambda model, _id: mock_node if model.__name__ == "Node" else mock_task

    mock_parent = MagicMock()
    mock_parent.to_dict.return_value = {"id": 99, "sha256": "a" * 64}

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": {"task_ids": [777]}}

    with (
        patch("utils.dist.dist_transaction") as mock_tx,
        patch("utils.dist.main_db") as mock_main_db,
        patch("utils.dist.http_session.post", return_value=mock_response) as mock_post,
    ):
        mock_tx.return_value.__enter__.return_value = mock_db
        mock_main_db.get_parent_sample_from_task.return_value = mock_parent
        result = node_submit_task(task_id=100, node_id=7, main_task_id=500)

    assert result is True
    posted_data = mock_post.call_args.kwargs["data"]
    assert json.loads(posted_data["attributes"]) == {
        "main_task_id": 500,
        "parent_sample": {"id": 99, "sha256": "a" * 64},
    }


def test_create_session_registers_atexit_dispose(monkeypatch):
    import atexit
    from lib.cuckoo.common.dist_db import create_session

    registered = []
    monkeypatch.setattr(atexit, "register", lambda fn, *a, **k: registered.append(fn))

    maker = create_session("sqlite:///:memory:", echo=False)
    engine = maker.kw["bind"]
    assert engine.dispose in registered
    engine.dispose()


def test_create_session_postgresql_configuration(monkeypatch):
    import atexit
    from unittest.mock import MagicMock, patch
    from lib.cuckoo.common.dist_db import create_session

    monkeypatch.setattr(atexit, "register", lambda fn, *a, **k: None)

    mock_engine = MagicMock()
    with (
        patch("lib.cuckoo.common.dist_db.create_engine", return_value=mock_engine) as mock_create_engine,
        patch("lib.cuckoo.common.dist_db.Base.metadata.create_all"),
    ):
        maker = create_session("postgresql://user:pass@localhost:5432/cuckoo_dist", echo=False)
        mock_create_engine.assert_called_once_with(
            "postgresql://user:pass@localhost:5432/cuckoo_dist",
            echo=False,
            pool_pre_ping=True,
            pool_recycle=1800,
            connect_args={
                "keepalives": 1,
                "keepalives_idle": 60,
                "keepalives_interval": 10,
                "keepalives_count": 5,
            },
        )
        assert maker.kw["bind"] == mock_engine

    # Also verify SQLite works without connect_args or pool_recycle
    sqlite_maker = create_session("sqlite:///:memory:", echo=False)
    sqlite_engine = sqlite_maker.kw["bind"]
    assert sqlite_engine.url.drivername == "sqlite"
    sqlite_engine.dispose()


def test_node_fetch_tasks_timeout():
    import sys
    from unittest.mock import MagicMock, patch

    mock_fastapi = MagicMock()
    if "fastapi" not in sys.modules:
        sys.modules["fastapi"] = mock_fastapi
        sys.modules["fastapi.security"] = mock_fastapi.security

    from utils.dist import node_fetch_tasks

    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {"data": [{"id": 1}]}

    with patch("utils.dist.http_session.get", return_value=mock_resp) as mock_get:
        tasks = node_fetch_tasks("completed", "http://worker:8000", "testkey", action="fetch", since=100)
        assert tasks == [{"id": 1}]
        mock_get.assert_called_once()
        assert mock_get.call_args.kwargs.get("timeout") == 30



# ---- Transaction boundaries and loop-level disconnect handling (utils/dist.py) ----


def _operational_error(msg="server closed the connection unexpectedly"):
    from sqlalchemy.exc import OperationalError

    return OperationalError("SELECT 1", {}, Exception(msg))


@pytest.fixture
def dist_sqlite(monkeypatch, tmp_path):
    """Point utils.dist at a real file-backed SQLite dist DB (one connection pool, checkout tracking)."""
    import atexit

    import utils.dist as dist
    from lib.cuckoo.common.dist_db import create_session

    monkeypatch.setattr(atexit, "register", lambda fn, *a, **k: None)
    maker = create_session(f"sqlite:///{tmp_path / 'dist.db'}", echo=False)
    monkeypatch.setattr(dist, "_session_maker", maker)
    yield maker
    maker.kw["bind"].dispose()


def _add_node_and_task(maker, node_name="worker1", category="url", path="http://example.test", node_id=None, task_id=None):
    with maker() as s, s.begin():
        node = Node(name=node_name, url="http://worker1.local/", apikey="k", enabled=True)
        s.add(node)
        s.flush()
        task = Task(path=path, category=category, package="", timeout=1, priority=1, options="", machine="",
                    platform="windows", tags="", custom="", memory=False, clock=None, enforce_timeout=False, main_task_id=500)
        task.node_id = node_id
        task.task_id = task_id
        s.add(task)
        s.flush()
        return node.id, task.id


def test_dist_transaction_commits_and_rolls_back(dist_sqlite):
    from sqlalchemy import func, select

    from utils.dist import dist_transaction

    with dist_transaction() as db:
        db.add(Node(name="a", url="u", apikey="k"))

    with pytest.raises(RuntimeError):
        with dist_transaction() as db:
            db.add(Node(name="b", url="u", apikey="k"))
            db.flush()
            raise RuntimeError("boom")

    with dist_transaction() as db:
        assert db.scalars(select(Node.name)).all() == ["a"]
        assert db.scalar(select(func.count()).select_from(Node)) == 1
    # Every block returned its connection to the pool.
    assert dist_sqlite.kw["bind"].pool.checkedout() == 0


def test_dist_objects_readable_after_commit(dist_sqlite):
    """expire_on_commit=False: attributes loaded in a block stay readable after it commits."""
    from sqlalchemy import select

    from utils.dist import dist_transaction

    _add_node_and_task(dist_sqlite)
    with dist_transaction() as db:
        node = db.scalar(select(Node).where(Node.name == "worker1"))
    assert node.url == "http://worker1.local/"


def test_is_db_disconnect_and_handle_loop_error():
    from unittest.mock import patch

    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.exc import TimeoutError as SQLTimeoutError

    from utils.dist import handle_loop_error, is_db_disconnect

    assert is_db_disconnect(_operational_error())
    assert is_db_disconnect(SQLTimeoutError("QueuePool limit of size 5 overflow 10 reached"))
    assert not is_db_disconnect(IntegrityError("INSERT", {}, Exception("dup")))
    assert not is_db_disconnect(ValueError("x"))

    with patch("utils.dist.restart_db_connection") as mock_restart:
        handle_loop_error("unit", _operational_error("SSL connection has been closed unexpectedly"))
        mock_restart.assert_called_once()
    with patch("utils.dist.restart_db_connection") as mock_restart:
        handle_loop_error("unit", ValueError("not a db error"))
        mock_restart.assert_not_called()


def test_restart_db_connection_disposes_engine():
    from unittest.mock import MagicMock, patch

    from utils.dist import restart_db_connection

    mock_bind = MagicMock()
    with patch("utils.dist._session_maker") as mock_maker:
        mock_maker.kw = {"bind": mock_bind}
        restart_db_connection()
    mock_bind.dispose.assert_called_once()


def test_node_submit_task_holds_no_transaction_during_http(dist_sqlite):
    """The upload to the node runs with no dist connection checked out; the result is written afterwards."""
    from unittest.mock import MagicMock, patch

    from utils.dist import node_submit_task

    node_id, task_id = _add_node_and_task(dist_sqlite)
    engine = dist_sqlite.kw["bind"]
    checked_out_during_post = []

    def fake_post(*args, **kwargs):
        checked_out_during_post.append(engine.pool.checkedout())
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"data": {"task_ids": [777]}}
        return resp

    with patch("utils.dist.http_session.post", side_effect=fake_post):
        assert node_submit_task(task_id, node_id, 500) is True

    assert checked_out_during_post == [0]
    with dist_sqlite() as s:
        task = s.get(Task, task_id)
        assert task.task_id == 777
        assert task.node_id == node_id


def test_fetcher_retries_unit_of_work_after_disconnect(dist_sqlite):
    """A DB disconnect in one fetcher pass resets the pool and the next pass redoes the whole unit of work."""
    import contextlib
    import queue
    import threading
    from unittest.mock import patch

    import utils.dist as dist

    node_id, _ = _add_node_and_task(dist_sqlite, node_id=None, task_id=None)
    with dist_sqlite() as s, s.begin():
        task = s.scalars(dist.select(Task)).one()
        task.node_id = node_id
        task.task_id = 42

    retriever = dist.Retriever()
    retriever.stop_dist = threading.Event()
    retriever.status_count = {}
    retriever.current_queue = {}
    retriever.fetcher_queue = queue.Queue()

    real_tx = dist.dist_transaction
    calls = {"n": 0}

    @contextlib.contextmanager
    def flaky_tx():
        calls["n"] += 1
        if calls["n"] == 1:
            raise _operational_error()
        with real_tx() as db:
            yield db

    class StopLoop(Exception):
        pass

    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise StopLoop()

    with (
        patch("utils.dist.dist_transaction", side_effect=flaky_tx),
        patch("utils.dist.node_fetch_tasks", return_value=[{"id": 42}]),
        patch("utils.dist.restart_db_connection") as mock_restart,
        patch("utils.dist.time.sleep", side_effect=fake_sleep),
    ):
        with pytest.raises(StopLoop):
            retriever.fetcher()

    mock_restart.assert_called_once()
    assert sleeps == [5, 5]
    assert list(retriever.fetcher_queue.queue) == [({"id": 42}, node_id)]


def test_fetch_report_nfs_marks_retrieved_and_keeps_failed_copy(dist_sqlite, tmp_path):
    import queue
    import threading
    from unittest.mock import MagicMock, patch

    import utils.dist as dist

    node_id, task_pk = _add_node_and_task(dist_sqlite, category="url", path=str(tmp_path / "missing"))
    with dist_sqlite() as s, s.begin():
        t = s.get(Task, task_pk)
        t.node_id = node_id
        t.task_id = 9

    retriever = dist.Retriever()
    retriever.stop_dist = threading.Event()
    retriever.cleaner_queue = queue.Queue()
    retriever.t_is_none = {}

    with (
        patch("utils.dist.main_db", MagicMock()),
        patch("utils.dist.node_get_report_nfs", return_value=False),
        patch("utils.dist.GCS_ENABLED", False, create=True),
    ):
        assert retriever._fetch_report_nfs({"id": 9}, node_id) is False
    with dist_sqlite() as s:
        assert s.get(Task, task_pk).retrieved is False

    engine = dist_sqlite.kw["bind"]
    seen = []

    def fake_copy(*args):
        seen.append(engine.pool.checkedout())
        return True

    with (
        patch("utils.dist.main_db", MagicMock()),
        patch("utils.dist.node_get_report_nfs", side_effect=fake_copy),
        patch("utils.dist.GCS_ENABLED", False, create=True),
    ):
        assert retriever._fetch_report_nfs({"id": 9}, node_id) is True
    assert seen == [0]
    with dist_sqlite() as s:
        t = s.get(Task, task_pk)
        assert t.retrieved is True and t.finished is True


def test_submit_tasks_failed_submission_bans_and_deletes(dist_sqlite):
    """Unsubmittable tasks are banned in CAPE and removed from the dist DB after the parallel upload."""
    from unittest.mock import MagicMock, patch

    import utils.dist as dist

    node_id, task_pk = _add_node_and_task(dist_sqlite)
    mock_main_db = MagicMock()
    mock_main_db.list_tasks.return_value = []

    seen = []

    def fake_submit(dist_id, nid, main_id):
        seen.append(dist_sqlite.kw["bind"].pool.checkedout())
        return False

    with (
        patch("utils.dist.main_db", mock_main_db),
        patch("utils.dist.node_submit_task", side_effect=fake_submit),
        patch.dict("utils.dist.SERVER_TAGS", {"worker1": []}),
    ):
        status = dist.StatusThread()
        # list_tasks returns nothing -> submit_tasks returns early; call the upload stage directly.
        results = status._submit_parallel(node_id, [(task_pk, 500)])
    assert results == [((task_pk, 500), False, False)]
    assert seen == [0]

    # Full pass: one pending CAPE task is claimed into a new dist row (claim transaction), uploaded with no
    # transaction open, and on failure banned in CAPE + deleted from the dist DB (result transaction).
    from types import SimpleNamespace

    pending = SimpleNamespace(
        id=501, category="url", target="http://example.test", options="", tags=[], package="", timeout=1, priority=1,
        machine="", platform="windows", custom="", memory=False, clock=None, enforce_timeout=False, route=None, tlp=None,
    )
    mock_main_db.list_tasks.return_value = [pending]
    seen.clear()
    with (
        patch("utils.dist.main_db", mock_main_db),
        patch("utils.dist.node_submit_task", side_effect=fake_submit),
        patch.object(dist.StatusThread, "load_vm_tags"),
        patch.dict("utils.dist.SERVER_TAGS", {"worker1": []}),
    ):
        assert dist.StatusThread().submit_tasks("worker1", 5) is True

    assert seen == [0]
    # The seeded orphan dist row (no node_id/task_id) was recycled to PENDING by the bad-task sweep.
    mock_main_db.set_status.assert_any_call(500, dist.TASK_PENDING)
    mock_main_db.set_status.assert_any_call(501, dist.TASK_BANNED)
    with dist_sqlite() as s:
        assert s.scalars(dist.select(Task)).all() == []


def test_cron_cleaner_marks_deleted_per_node(dist_sqlite, monkeypatch, tmp_path):
    from unittest.mock import patch

    import utils.dist as dist

    with dist_sqlite() as s, s.begin():
        good = Node(name="good", url="http://good/", apikey="k", enabled=True)
        bad = Node(name="bad", url="http://bad/", apikey="k", enabled=True)
        s.add_all([good, bad])
        s.flush()
        for node, wid in ((good, 1), (bad, 2)):
            t = Task(path="p", category="url", package="", timeout=1, priority=1, options="", machine="", platform="",
                     tags="", custom="", memory=False, clock=None, enforce_timeout=False, main_task_id=wid)
            t.node_id = node.id
            t.task_id = wid
            t.notificated = True
            s.add(t)
        good_id, bad_id = good.id, bad.id

    monkeypatch.setattr(dist, "CUCKOO_ROOT", str(tmp_path))
    with patch("utils.dist._delete_many", side_effect=lambda node_id, ids, nodes: node_id == good_id):
        dist.cron_cleaner()

    with dist_sqlite() as s:
        rows = {t.node_id: t.deleted for t in s.scalars(dist.select(Task))}
    assert rows == {good_id: True, bad_id: False}


# ---- Fixes for previously broken paths in utils/dist.py ----


def test_gcs_defaults_defined_when_gcp_disabled():
    import utils.dist as dist

    if dist.gcp_conf.samples_pubsub.enabled:
        pytest.skip("GCP samples_pubsub enabled in this config")
    assert dist.GCS_ENABLED is False
    assert dist.gcs_uploader is None
    assert dist.gcs_upload_report is None and dist.gcs_replay is None


def test_load_vm_tags_handles_null_tags(dist_sqlite):
    import utils.dist as dist

    with dist_sqlite() as s, s.begin():
        node = Node(name="tagnode", url="u", apikey="k", enabled=True)
        s.add(node)
        s.flush()
        m1 = Machine(name="vm1", platform="windows", tags=None)
        m1.node_id = node.id
        m2 = Machine(name="vm2", platform="windows", tags=["x64", "win10"])
        m2.node_id = node.id
        s.add_all([m1, m2])
        node_id = node.id

    with patch_dict_server_tags() as tags:
        with dist.dist_transaction() as db:
            dist.StatusThread().load_vm_tags(db, node_id, "tagnode")
        assert sorted(tags["tagnode"]) == ["win10", "x64", "x64,win10"]


def patch_dict_server_tags():
    from unittest.mock import patch

    import utils.dist as dist

    return patch.dict(dist.SERVER_TAGS, {}, clear=True)


def test_delete_vm_on_node_removes_machine_row(dist_sqlite, caplog):
    import logging

    import utils.dist as dist

    with dist_sqlite() as s, s.begin():
        node = Node(name="vmnode", url="u", apikey="k", enabled=True)
        s.add(node)
        s.flush()
        for name in ("keep", "drop"):
            m = Machine(name=name, platform="windows", tags=[])
            m.node_id = node.id
            s.add(m)

    dist.delete_vm_on_node("vmnode", "drop")
    with dist_sqlite() as s:
        assert s.scalars(dist.select(Machine.name)).all() == ["keep"]

    with caplog.at_level(logging.ERROR):
        dist.delete_vm_on_node("vmnode", "missing")
        dist.delete_vm_on_node("nonode", "keep")
    assert "The selected VM does not exist" in caplog.text
    assert "Node nonode does not exist" in caplog.text


def test_notification_pass_marks_only_accepted_tasks(dist_sqlite):
    from unittest.mock import MagicMock, patch

    import requests

    import utils.dist as dist

    with dist_sqlite() as s, s.begin():
        for main_id in (11, 12):
            t = Task(path="p", category="url", package="", timeout=1, priority=1, options="", machine="", platform="",
                     tags="", custom="", memory=False, clock=None, enforce_timeout=False, main_task_id=main_id)
            t.finished = True
            t.retrieved = True
            s.add(t)

    engine = dist_sqlite.kw["bind"]
    seen = []

    def fake_post(url, headers=None, data=None, timeout=None):
        seen.append(engine.pool.checkedout())
        assert timeout
        if '"task_id": 12' in data:
            raise requests.ConnectionError("down")
        resp = MagicMock()
        resp.ok = True
        return resp

    mock_main_db = MagicMock()
    with (
        patch("utils.dist.main_db", mock_main_db),
        patch("utils.dist.http_session.post", side_effect=fake_post),
    ):
        dist.Retriever()._notification_pass(["http://cb"], {"x-api-key": "k"})

    assert seen == [0, 0]
    mock_main_db.set_status.assert_any_call(11, dist.TASK_REPORTED)
    mock_main_db.set_status.assert_any_call(12, dist.TASK_REPORTED)
    with dist_sqlite() as s:
        flags = {t.main_task_id: t.notificated for t in s.scalars(dist.select(Task))}
    assert flags == {11: True, 12: False}


def test_retriever_run_restapi_mode_logs_critical_instead_of_attributeerror(caplog):
    import logging
    from unittest.mock import patch

    import utils.dist as dist

    class StopSupervisor(Exception):
        pass

    started = []

    class FakeThread:
        def __init__(self, target=None, name=None, args=()):
            started.append(name)
            self.daemon = False

        def start(self):
            pass

        def is_alive(self):
            return True

    with (
        patch("utils.dist.NFS_FETCH", False),
        patch("utils.dist.RESTAPI_FETCH", True),
        patch("utils.dist.threading.Thread", FakeThread),
        patch("utils.dist.time.sleep", side_effect=StopSupervisor),
        caplog.at_level(logging.CRITICAL),
    ):
        with pytest.raises(StopSupervisor):
            dist.Retriever.run(dist.Retriever())

    assert "restapi report retrieval is no longer supported" in caplog.text
    assert not any(name.startswith("api_") for name in started)
    assert "fetcher" in started


def test_node_submit_task_formats_datetime_clock_for_worker_api():
    from datetime import datetime
    from unittest.mock import MagicMock, patch

    from lib.cuckoo.common.dist_db import Node
    from utils.dist import node_submit_task

    mock_node = MagicMock(id=2, name="worker1", url="http://worker1/apiv2/", apikey="k")
    mock_task = MagicMock(
        id=10,
        main_task_id=44,
        category="url",
        path="http://example.test/",
        package="ie",
        timeout=120,
        priority=1,
        options="free=yes",
        machine="win10_1",
        platform="windows",
        tags="x64,",
        custom="",
        clock=datetime(2026, 10, 31, 14, 5, 9),
        memory=False,
        enforce_timeout=False,
        route="tor",
        tlp="AMBER",
    )
    mock_db = MagicMock()
    mock_db.get.side_effect = lambda model, pk: mock_node if model is Node else mock_task

    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"data": {"task_ids": [88]}}

    with (
        patch("utils.dist.dist_transaction") as mock_tx,
        patch("utils.dist.http_session.post", return_value=mock_resp) as mock_post,
    ):
        mock_tx.return_value.__enter__.return_value = mock_db
        assert node_submit_task(10, 2, 44) is True

    posted = mock_post.call_args.kwargs["data"]
    assert posted["clock"] == "10-31-2026 14:05:09"
    assert posted["url"] == "http://example.test/"
    assert posted["machine"] == "win10_1"
    assert posted["tags"] == "x64"
    assert posted["route"] == "tor"
    assert posted["tlp"] == "AMBER"


def test_dist_defines_gcs_enabled_when_gcp_disabled():
    import utils.dist as dist_mod

    assert hasattr(dist_mod, "GCS_ENABLED")
    assert isinstance(dist_mod.GCS_ENABLED, bool)


def test_node_submit_task_acl_probe_skips_object_storage_upload_and_marks_url_failure():
    from http.client import RemoteDisconnected
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    from lib.cuckoo.common.dist_db import Node
    from lib.cuckoo.core.data.task import TASK_FAILED_REPORTING
    from lib.tenancy.hooks import default_report_stamp_hook
    from utils.dist import node_submit_task

    upload_calls = []
    with (
        patch("lib.tenancy.storage.config.object_storage_config", return_value=SimpleNamespace(enabled=True)),
        patch("lib.tenancy.storage.reporting.upload_analysis_artifacts", side_effect=lambda r: upload_calls.append(r)),
    ):
        default_report_stamp_hook({"info": {"id": 99}}, stage="acl_probe")
    assert upload_calls == []

    mock_node = MagicMock(id=2, name="worker1", url="http://worker1/apiv2/", apikey="k")
    mock_task = MagicMock(
        id=10,
        main_task_id=44,
        category="url",
        path="http://example.test/",
        package="ie",
        timeout=120,
        priority=1,
        options="",
        machine="",
        platform="windows",
        tags="",
        custom="",
        clock="10-31-2026 14:05:09",
        memory=False,
        enforce_timeout=False,
        route="none",
        tlp="",
        finished=False,
        retrieved=False,
    )
    mock_db = MagicMock()
    mock_db.get.side_effect = lambda model, pk: mock_node if model is Node else mock_task

    hook_stages = []
    with (
        patch("utils.dist.dist_transaction") as mock_tx,
        patch("utils.dist.main_db") as mock_main_db,
        patch("urllib3.util.retry.time.sleep") as mock_sleep,
        patch("lib.cuckoo.common.hooks.run_report_hooks", side_effect=lambda r, **kw: hook_stages.append(kw.get("stage"))),
        patch(
            "urllib3.connectionpool.HTTPConnectionPool._make_request",
            side_effect=RemoteDisconnected("worker down"),
        ) as mock_make_request,
    ):
        mock_tx.return_value.__enter__.return_value = mock_db
        node_submit_task(10, 2, 44)

    assert hook_stages == ["acl_probe"]
    assert mock_make_request.call_count == 4
    assert mock_sleep.call_count == 2
    assert mock_task.finished is True
    assert mock_task.retrieved is True
    mock_main_db.set_status.assert_called_once_with(44, TASK_FAILED_REPORTING)


def test_node_submit_task_retries_transient_disconnect_and_replays_file_body(tmp_path):
    from http.client import RemoteDisconnected
    import io
    from unittest.mock import MagicMock, patch

    from urllib3.response import HTTPResponse

    from lib.cuckoo.common.dist_db import Node
    from utils.dist import node_submit_task

    sample_file = tmp_path / "sample.bin"
    sample_bytes = b"MZ" + b"A" * 128
    sample_file.write_bytes(sample_bytes)

    mock_node = MagicMock(id=2, name="worker1", url="http://worker1/apiv2/", apikey="k")
    mock_task = MagicMock(
        id=10,
        main_task_id=44,
        category="file",
        path=str(sample_file),
        package="",
        timeout=120,
        priority=1,
        options="",
        machine="",
        platform="windows",
        tags="",
        custom="",
        clock="10-31-2026 14:05:09",
        memory=False,
        enforce_timeout=False,
        route="none",
        tlp="",
        finished=False,
        retrieved=False,
    )
    mock_db = MagicMock()
    mock_db.get.side_effect = lambda model, pk: mock_node if model is Node else mock_task

    sent_bodies = []

    def fake_make_request(conn, method, url, **kwargs):
        sent_bodies.append(kwargs.get("body", b""))
        if len(sent_bodies) < 3:
            raise RemoteDisconnected("Remote end closed connection without response")
        return HTTPResponse(
            body=io.BytesIO(b'{"data": {"task_ids": [901]}}'),
            status=200,
            preload_content=False,
        )

    with (
        patch("utils.dist.dist_transaction") as mock_tx,
        patch("utils.dist.main_db") as mock_main_db,
        patch("urllib3.util.retry.time.sleep") as mock_sleep,
        patch("urllib3.connectionpool.HTTPConnectionPool._make_request", side_effect=fake_make_request),
    ):
        mock_tx.return_value.__enter__.return_value = mock_db
        mock_main_db.get_parent_sample_from_task.return_value = None
        assert node_submit_task(10, 2, 44) is True

    assert len(sent_bodies) == 3
    assert all(sample_bytes in body for body in sent_bodies)
    assert sent_bodies[0] == sent_bodies[1] == sent_bodies[2]
    assert mock_sleep.call_count == 1
    assert mock_task.task_id == 901
    assert mock_task.node_id == 2
    assert mock_task.finished is False
    mock_main_db.set_status.assert_not_called()


def test_wrapped_validate_task_resolves_fallback_owner_for_recovered_task():
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    from lib.tenancy.hooks import wrap_submission_and_web_utils
    from lib.tenancy.policy import ViewerContext

    fake_web_utils = SimpleNamespace(
        validate_task=lambda tid: {"error": False, "rtid": 77, "tlp": None},
    )
    wrap_submission_and_web_utils(web_utils_mod=fake_web_utils)

    fake_db = MagicMock()
    fake_db.session.get.side_effect = lambda model, pk: SimpleNamespace(user_id=101) if pk == 77 else None

    viewer = ViewerContext(user_id=101, tenant_id=None)
    with (
        patch("lib.tenancy.hooks.get_current_viewer", return_value=viewer),
        patch("lib.cuckoo.core.database.Database", return_value=fake_db),
        patch("lib.tenancy.hooks.ensure_acl_schema_once"),
        patch(
            "lib.tenancy.hooks.resolve_task_scope",
            side_effect=lambda session, tid, fallback_user_id=None: SimpleNamespace(
                owner_id=fallback_user_id, tenant_id=None, visibility="private"
            ),
        ),
    ):
        res = fake_web_utils.validate_task(12)

    assert res == {"error": False, "rtid": 77, "tlp": None}


def test_sync_sharded_files_nfs_copies_sharded_and_flat_targets_and_rewrites_symlinks(tmp_path, monkeypatch):
    import hashlib
    import os
    from lib.cuckoo.common import utils as cuckoo_utils
    import utils.dist as dist_mod

    master_root = tmp_path / "master"
    worker_root = tmp_path / "worker_mount"
    monkeypatch.setattr(cuckoo_utils, "CUCKOO_ROOT", str(master_root))

    payload_sharded = b"worker-sharded-artifact"
    sha_sharded = hashlib.sha256(payload_sharded).hexdigest()
    worker_sharded_file = worker_root / "storage" / "files" / sha_sharded[:2] / sha_sharded[2:4] / sha_sharded
    worker_sharded_file.parent.mkdir(parents=True)
    worker_sharded_file.write_bytes(payload_sharded)

    payload_flat = b"worker-flat-legacy-artifact"
    sha_flat = hashlib.sha256(payload_flat).hexdigest()
    worker_flat_file = worker_root / "storage" / "files" / sha_flat
    worker_flat_file.write_bytes(payload_flat)

    analyses_dir = master_root / "storage" / "analyses" / "42"
    (analyses_dir / "files").mkdir(parents=True)
    (analyses_dir / "selfextracted").mkdir(parents=True)

    # Simulate symlinks copied from worker with symlinks=True (pointing to worker-local /opt/CAPEv2/storage/files/...)
    link_sharded = analyses_dir / "files" / sha_sharded
    os.symlink(f"/opt/CAPEv2/storage/files/{sha_sharded[:2]}/{sha_sharded[2:4]}/{sha_sharded}", str(link_sharded))

    link_flat = analyses_dir / "selfextracted" / sha_flat
    os.symlink(f"/opt/CAPEv2/storage/files/{sha_flat}", str(link_flat))

    dist_mod.sync_sharded_files_nfs(str(worker_root), str(analyses_dir))

    expected_master_sharded = master_root / "storage" / "files" / sha_sharded[:2] / sha_sharded[2:4] / sha_sharded
    expected_master_flat = master_root / "storage" / "files" / sha_flat[:2] / sha_flat[2:4] / sha_flat
    assert expected_master_sharded.read_bytes() == payload_sharded
    assert expected_master_flat.read_bytes() == payload_flat
    assert os.readlink(link_sharded) == str(expected_master_sharded)
    assert os.readlink(link_flat) == str(expected_master_flat)
    assert link_sharded.read_bytes() == payload_sharded
    assert link_flat.read_bytes() == payload_flat


def test_save_dist_error_html_routes_to_cape_external_and_handles_oserror(tmp_path, monkeypatch):
    from unittest.mock import MagicMock, patch

    import utils.dist as dist_mod

    ext_dir = tmp_path / "cape-external"
    ext_dir.mkdir()
    monkeypatch.setattr(dist_mod, "get_cape_external_dir", lambda: str(ext_dir))

    written = dist_mod._save_dist_error_html(b"<html>500</html>")
    assert written == str(ext_dir / "dist_error.html")
    assert (ext_dir / "dist_error.html").read_bytes() == b"<html>500</html>"

    # Non-ok worker response writes to cape-external/dist_error.html and returns None.
    fake_resp = MagicMock(ok=False, status_code=500, url="http://worker/apiv2/tasks/list/", content=b"<html>node-err</html>")
    with patch.object(dist_mod.http_session, "get", return_value=fake_resp):
        assert dist_mod.node_fetch_tasks("reported", "http://worker/apiv2/", "key") is None
    assert (ext_dir / "dist_error.html").read_bytes() == b"<html>node-err</html>"

    # node_submit_task 500 error also routes dist_error.html into cape-external.
    mock_node = MagicMock(id=2, name="worker1", url="http://worker1/apiv2/", apikey="k")
    mock_task = MagicMock(
        id=10,
        main_task_id=44,
        category="url",
        path="https://example.invalid/",
        package="",
        timeout=120,
        priority=1,
        options="",
        machine="",
        platform="windows",
        tags="",
        custom="",
        clock="10-31-2026 14:05:09",
        memory=False,
        enforce_timeout=False,
        route="none",
        tlp="",
        finished=False,
        retrieved=False,
    )
    mock_db = MagicMock()
    mock_db.get.side_effect = lambda model, _pk: mock_node if model is dist_mod.Node else mock_task
    submit_500 = MagicMock(status_code=500, content=b"<html>submit-500</html>", text="submit error")
    with (
        patch("utils.dist.dist_transaction") as mock_tx,
        patch("utils.dist.main_db") as mock_main_db,
        patch.object(dist_mod.http_session, "post", return_value=submit_500),
    ):
        mock_tx.return_value.__enter__.return_value = mock_db
        mock_main_db.get_parent_sample_from_task.return_value = None
        assert dist_mod.node_submit_task(10, 2, 44) is False
    assert (ext_dir / "dist_error.html").read_bytes() == b"<html>submit-500</html>"

    # ENOSPC / OSError writing dist_error.html does not raise.
    with patch.object(dist_mod, "path_write_file", side_effect=OSError("disk full")):
        assert dist_mod._save_dist_error_html(b"ignored") is None


def test_retriever_free_space_mon_and_backpressure(tmp_path, monkeypatch):
    import queue
    import threading
    from unittest.mock import patch

    import pytest

    import utils.dist as dist_mod

    # 1. Skips immediately when freespace == 0.
    retriever = dist_mod.Retriever()
    retriever.stop_dist = threading.Event()
    retriever.low_disk_space = threading.Event()

    monkeypatch.setitem(dist_mod.cfg.cuckoo, "freespace", 0)
    with patch.object(dist_mod, "free_space_monitor") as mock_fsm:
        retriever.free_space_mon()
    mock_fsm.assert_not_called()

    # 2. Checks both analyses and cape-external when on different filesystems; skips duplicate st_dev.
    ext_dir = tmp_path / "cape-external"
    ext_dir.mkdir()
    analyses_dir = tmp_path / "storage" / "analyses"
    analyses_dir.mkdir(parents=True)

    checked_paths = []

    def _record_fsm(path, analysis=False, on_state_change=None, should_stop=None):
        checked_paths.append((path, analysis, on_state_change, should_stop))

    monkeypatch.setitem(dist_mod.cfg.cuckoo, "freespace", 500)
    with (
        patch.object(dist_mod, "CUCKOO_ROOT", str(tmp_path)),
        patch.object(dist_mod, "get_cape_external_dir", return_value=str(ext_dir)),
        patch.object(retriever, "_resolve_st_dev", side_effect=[101, 202]),
        patch.object(dist_mod, "free_space_monitor", side_effect=_record_fsm),
        patch.object(dist_mod.time, "sleep", side_effect=lambda _s: retriever.stop_dist.set()),
    ):
        retriever.free_space_mon()

    assert [c[0] for c in checked_paths] == [str(analyses_dir.resolve()), str(ext_dir.resolve())]
    assert all(
        c[1] is True and c[2] == retriever._on_space_state_change and callable(c[3]) for c in checked_paths
    )

    checked_paths.clear()
    retriever.stop_dist.clear()
    with (
        patch.object(dist_mod, "CUCKOO_ROOT", str(tmp_path)),
        patch.object(dist_mod, "get_cape_external_dir", return_value=str(ext_dir)),
        patch.object(retriever, "_resolve_st_dev", side_effect=[101, 101]),
        patch.object(dist_mod, "free_space_monitor", side_effect=_record_fsm),
        patch.object(dist_mod.time, "sleep", side_effect=lambda _s: retriever.stop_dist.set()),
    ):
        retriever.free_space_mon()

    assert [c[0] for c in checked_paths] == [str(analyses_dir.resolve())]

    # 3. _on_space_state_change toggles low_disk_space Event; exceptions caught cleanly in free_space_mon.
    retriever._on_space_state_change(True, 25)
    assert retriever.low_disk_space.is_set()
    retriever._on_space_state_change(False, 900)
    assert not retriever.low_disk_space.is_set()

    retriever.stop_dist.clear()
    loop_errors = []

    def _boom_fsm(*_args, **_kwargs):
        retriever.stop_dist.set()
        raise RuntimeError("fsm failure")

    with (
        patch.object(dist_mod, "CUCKOO_ROOT", str(tmp_path)),
        patch.object(dist_mod, "get_cape_external_dir", return_value=str(ext_dir)),
        patch.object(dist_mod, "free_space_monitor", side_effect=_boom_fsm),
        patch.object(dist_mod, "handle_loop_error", side_effect=lambda name, exc: loop_errors.append((name, str(exc)))),
    ):
        retriever.free_space_mon()
    assert loop_errors == [("free_space_mon", "fsm failure")]

    # 4. fetcher pauses while low_disk_space is set and resumes when cleared.
    class _StopLoop(BaseException):
        pass

    retriever = dist_mod.Retriever()
    retriever.stop_dist = threading.Event()
    retriever.low_disk_space = threading.Event()
    retriever.low_disk_space.set()
    fetcher_passes = []
    fetcher_sleeps = []

    def _fetcher_sleep(sec):
        fetcher_sleeps.append(sec)
        if len(fetcher_sleeps) == 1:
            assert fetcher_passes == []
            retriever.low_disk_space.clear()
        else:
            raise _StopLoop

    with (
        patch.object(retriever, "_fetcher_pass", side_effect=lambda lc: fetcher_passes.append(dict(lc))),
        patch.object(dist_mod.time, "sleep", side_effect=_fetcher_sleep),
    ):
        with pytest.raises(_StopLoop):
            retriever.fetcher()
    assert fetcher_sleeps == [5, 5]
    assert len(fetcher_passes) == 1

    # 5. fetch_latest_reports_nfs pauses while low_disk_space is set and resumes when cleared.
    retriever = dist_mod.Retriever()
    retriever.stop_dist = threading.Event()
    retriever.low_disk_space = threading.Event()
    retriever.low_disk_space.set()
    retriever.current_queue = {}
    retriever.fetcher_queue = queue.Queue()
    retriever.fetcher_queue.put(({"id": 77}, 3))
    nfs_sleeps = []
    fetched = []

    def _nfs_sleep(sec):
        nfs_sleeps.append(sec)
        assert fetched == []
        assert not retriever.fetcher_queue.empty()
        retriever.low_disk_space.clear()

    def _fake_fetch_nfs(task, node_id):
        fetched.append((task["id"], node_id))
        raise _StopLoop

    with (
        patch.object(retriever, "_fetch_report_nfs", side_effect=_fake_fetch_nfs),
        patch.object(dist_mod.time, "sleep", side_effect=_nfs_sleep),
    ):
        with pytest.raises(_StopLoop):
            retriever.fetch_latest_reports_nfs()
    assert nfs_sleeps == [5]
    assert fetched == [(77, 3)]


