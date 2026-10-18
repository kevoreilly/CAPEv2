# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


from lib.cuckoo.common.dist_db import Machine, Node, StringList, Task


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


def test_session_wrapper_and_restart():
    import sys
    from unittest.mock import MagicMock, patch

    # Mock optional dependencies required by utils.dist module imports
    mock_fastapi = MagicMock()
    if "fastapi" not in sys.modules:
        sys.modules["fastapi"] = mock_fastapi
        sys.modules["fastapi.security"] = mock_fastapi.security

    from sqlalchemy.exc import TimeoutError as SQLTimeoutError
    from utils.dist import SessionWrapper, restart_db_connection

    # Test restart_db_connection when _session_maker has a bind kw
    mock_bind = MagicMock()
    with patch("utils.dist._session_maker") as mock_maker:
        mock_maker.kw = {"bind": mock_bind}
        restart_db_connection()
        mock_bind.dispose.assert_called_once()

    # Test SessionWrapper proxying and exception interception
    mock_inner_session = MagicMock()
    # Mocking commit to raise TimeoutError
    mock_inner_session.commit.side_effect = SQLTimeoutError("QueuePool limit of size 5 overflow 10 reached")

    wrapper = SessionWrapper(mock_inner_session)

    # Test __getattr__ delegation
    mock_inner_session.some_method = MagicMock(return_value="delegated")
    assert wrapper.some_method() == "delegated"

    # Test that exception triggers restart_db_connection
    with patch("utils.dist.restart_db_connection") as mock_restart:
        try:
            wrapper.commit()
        except SQLTimeoutError:
            pass
        mock_restart.assert_called_once()

    # Test that __exit__ with exception triggers restart_db_connection
    mock_inner_session.__exit__ = MagicMock()
    with patch("utils.dist.restart_db_connection") as mock_restart:
        try:
            with wrapper:
                raise SQLTimeoutError("QueuePool limit of size 5 overflow 10 reached")
        except SQLTimeoutError:
            pass
        mock_restart.assert_called_once()


def test_cli_admin_commands():
    from unittest.mock import MagicMock, patch
    from utils.dist import show_status_cli, list_nodes_cli, register_node_cli, modify_node_cli

    # Test show_status_cli
    with patch("utils.dist.session") as mock_sess:
        mock_db = MagicMock()
        mock_sess.return_value.__enter__.return_value = mock_db
        mock_db.execute.return_value.first.return_value = MagicMock(processing=1, processed=2, pending=3)

        with patch("builtins.print") as mock_print:
            show_status_cli()
            mock_print.assert_any_call("Processing tasks : 1")

    # Test list_nodes_cli
    with patch("utils.dist.session") as mock_sess:
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
        mock_node.machines.all.return_value = [mock_machine]
        mock_db.scalars.return_value.all.return_value = [mock_node]

        with patch("builtins.print") as mock_print:
            list_nodes_cli()
            assert any("master" in str(args[0]) for args, _ in mock_print.call_args_list)

    # Test register_node_cli
    with patch("utils.dist.session") as mock_sess:
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
    with patch("utils.dist.session") as mock_sess:
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
    mock_db.scalar.return_value = mock_node
    mock_db.get.return_value = mock_task

    # Mock response from requests.post
    mock_response = MagicMock()
    mock_response.status_code = 503
    mock_response.text = "Service Unavailable"
    # To simulate bool(r) is False (requests' Response behavior)
    mock_response.__bool__.return_value = False

    with patch("utils.dist.requests.post", return_value=mock_response) as mock_post:
        with caplog.at_level(logging.INFO):
            result = node_submit_task(task_id=16410102, node_id=42, main_task_id=3330442, db=mock_db)

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
    mock_db.scalar.return_value = mock_node
    mock_db.get.return_value = mock_task

    mock_parent = MagicMock()
    mock_parent.to_dict.return_value = {"id": 99, "sha256": "a" * 64}

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": {"task_ids": [777]}}

    with (
        patch("utils.dist.main_db") as mock_main_db,
        patch("utils.dist.requests.post", return_value=mock_response) as mock_post,
    ):
        mock_main_db.get_parent_sample_from_task.return_value = mock_parent
        result = node_submit_task(task_id=100, node_id=7, main_task_id=500, db=mock_db)

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

