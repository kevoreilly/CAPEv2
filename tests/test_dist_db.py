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
        
        with patch("utils.dist.node_list_machines", return_value=[]), \
             patch("utils.dist.node_list_exitnodes", return_value=[]), \
             patch("builtins.print") as mock_print:
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
