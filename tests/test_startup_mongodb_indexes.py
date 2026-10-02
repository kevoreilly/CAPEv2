from unittest.mock import Mock

import lib.cuckoo.core.startup as startup


def test_check_webgui_mongo_creates_calls_task_id_index(monkeypatch):
    create_index = Mock()

    monkeypatch.setattr(startup.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(startup.repconf.elasticsearchdb, "enabled", False)

    monkeypatch.setattr(
        "dev_utils.mongodb.connect_to_mongo",
        Mock(return_value=object()),
    )
    monkeypatch.setattr(
        "dev_utils.mongodb.mongo_create_index",
        create_index,
    )

    startup.check_webgui_mongo()

    create_index.assert_any_call(
        "calls",
        [("task_id", 1)],
        name="task_id_1",
    )


def test_check_webgui_mongo_can_fail_nonfatally(monkeypatch, caplog):
    monkeypatch.setattr(startup.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(
        "dev_utils.mongodb.connect_to_mongo",
        Mock(return_value=None),
    )

    startup.check_webgui_mongo(exit_on_connection_failure=False)

    assert "mongo isn't working" in caplog.text
