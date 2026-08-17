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
    mock_flask = MagicMock()
    mock_flask_restful = MagicMock()
    if "flask" not in sys.modules:
        sys.modules["flask"] = mock_flask
    if "flask_restful" not in sys.modules:
        sys.modules["flask_restful"] = mock_flask_restful

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
