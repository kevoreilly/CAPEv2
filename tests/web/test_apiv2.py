import pathlib
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.test import SimpleTestCase
from django.core.files.uploadedfile import SimpleUploadedFile

from lib.cuckoo.common.config import ConfigMeta
from lib.cuckoo.core.data.task import (
    TASK_BANNED,
    TASK_COMPLETED,
    TASK_DISTRIBUTED,
    TASK_DISTRIBUTED_COMPLETED,
    TASK_FAILED_ANALYSIS,
    TASK_FAILED_PROCESSING,
    TASK_FAILED_REPORTING,
    TASK_PENDING,
    TASK_RECOVERED,
    TASK_REPORTED,
    TASK_RUNNING,
    Task,
)

@pytest.fixture
def taskreprocess_enabled(custom_conf_path: pathlib.Path):
    with open(custom_conf_path / "api.conf", "wt") as fil:
        print("[taskreprocess]\nenabled = yes", file=fil)
    ConfigMeta.refresh()
    yield


@pytest.fixture
def dlnexeccreate_enabled(custom_conf_path: pathlib.Path):
    with open(custom_conf_path / "api.conf", "wt") as fil:
        print(
            "[dlnexeccreate]\n"
            "enabled = yes\n"
            "allmachines = no\n"
            "status = yes",
            file=fil,
        )
    ConfigMeta.refresh()
    yield


@pytest.mark.usefixtures("db", "tmp_cuckoo_root")
class ReprocessTask(SimpleTestCase):
    taskprocess_config = "lib.cuckoo.common.web_utils.apiconf.taskreprocess"
    """API configuration to patch in each test case."""

    def test_api_disabled(self):
        response = self.client.get("/apiv2/tasks/reprocess/1/")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        json_body = {"error": True, "error_value": "Task Reprocess API is Disabled"}
        assert response.json() == json_body

    @pytest.mark.usefixtures("taskreprocess_enabled")
    def test_task_does_not_exist(self):
        patch_target = "lib.cuckoo.core.database._Database.view_task"
        with patch(patch_target, return_value=None):
            response = self.client.get("/apiv2/tasks/reprocess/1/")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        json_body = {"error": True, "error_value": "Task ID does not exist in the database"}
        assert response.json() == json_body

    @pytest.mark.usefixtures("taskreprocess_enabled")
    def test_can_reprocess(self):
        task = Task()
        valid_status = (TASK_REPORTED, TASK_RECOVERED, TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING)
        patch_target = "lib.cuckoo.core.database._Database.view_task"
        with patch(patch_target, return_value=task):
            for status in valid_status:
                expected_response = {"error": False, "data": f"Task ID 1 with status {status} marked for reprocessing"}
                with self.subTest(status):
                    task.status = status
                    response = self.client.get("/apiv2/tasks/reprocess/1/")
                    assert response.status_code == 200
                    assert response.headers["content-type"] == "application/json"
                    assert response.json() == expected_response

    @pytest.mark.usefixtures("taskreprocess_enabled")
    def test_cant_reprocess(self):
        task = Task()
        invalid_status = (
            TASK_COMPLETED,
            TASK_FAILED_ANALYSIS,
            TASK_DISTRIBUTED_COMPLETED,
            TASK_BANNED,
            TASK_PENDING,
            TASK_RUNNING,
            TASK_DISTRIBUTED,
        )
        patch_target = "lib.cuckoo.core.database._Database.view_task"
        with patch(patch_target, return_value=task):
            for status in invalid_status:
                expected_response = {"error": True, "error_value": f"Task ID 1 cannot be reprocessed in status {status}"}
                with self.subTest(status):
                    task.status = status
                    response = self.client.get("/apiv2/tasks/reprocess/1/")
                    assert response.status_code == 200
                    assert response.headers["content-type"] == "application/json"
                    assert response.json() == expected_response


@pytest.mark.usefixtures("db", "tmp_cuckoo_root")
class TestReservedMachineSubmission(SimpleTestCase):
    def test_url_submission_accepts_explicit_reserved_machine(self):
        normal_machine = SimpleNamespace(label="normal-machine")
        reserved_machine = SimpleNamespace(label="reserved-machine")

        def list_machines(*args, **kwargs):
            if kwargs.get("include_reserved"):
                return [normal_machine, reserved_machine]
            return [normal_machine]

        with (
            patch(
                "apiv2.views.db.list_machines",
                side_effect=list_machines,
            ),
            patch(
                "apiv2.views.db.add_url",
                return_value=123,
            ) as add_url,
        ):
            response = self.client.post(
                "/apiv2/tasks/create/url/",
                {
                    "url": "https://example.com/",
                    "machine": "reserved-machine",
                },
            )

        assert response.status_code == 200
        assert response.json()["data"]["task_ids"] == [123]
        add_url.assert_called_once()
        assert add_url.call_args.kwargs["machine"] == "reserved-machine"

    def test_file_submission_accepts_explicit_reserved_machine(self):
        normal_machine = SimpleNamespace(label="normal-machine")
        reserved_machine = SimpleNamespace(label="reserved-machine")

        def list_machines(*args, **kwargs):
            if kwargs.get("include_reserved"):
                return [normal_machine, reserved_machine]
            return [normal_machine]

        uploaded_file = SimpleUploadedFile(
            "sample.exe",
            b"MZ-test-content",
            content_type="application/octet-stream",
        )

        processed_details = {
            "errors": [],
            "task_ids": [123],
        }

        with (
            patch(
                "apiv2.views.db.list_machines",
                side_effect=list_machines,
            ),
            patch(
                "apiv2.views.process_new_task_files",
                return_value=(
                    [(b"MZ-test-content", b"/tmp/sample.exe", "test-sha256")],
                    processed_details,
                ),
            ),
            patch(
                "apiv2.views.download_file",
                return_value=("ok", {"task_ids": [123], "errors": []}),
            ),
        ):
            response = self.client.post(
                "/apiv2/tasks/create/file/",
                {
                    "file": uploaded_file,
                    "machine": "reserved-machine",
                },
            )

        assert response.status_code == 200
        assert response.json()["data"]["task_ids"] == [123]

    @pytest.mark.usefixtures("dlnexeccreate_enabled")
    def test_dlnexec_submission_accepts_explicit_reserved_machine(self):
        normal_machine = SimpleNamespace(label="normal-machine")
        reserved_machine = SimpleNamespace(label="reserved-machine")

        def list_machines(*args, **kwargs):
            if kwargs.get("include_reserved"):
                return [normal_machine, reserved_machine]
            return [normal_machine]

        with (
            patch(
                "apiv2.views.db.list_machines",
                side_effect=list_machines,
            ),
            patch(
                "apiv2.views.process_new_dlnexec_task",
                return_value=(
                    b"/tmp/downloaded.exe",
                    b"MZ-test-content",
                    "",
                ),
            ),
            patch(
                "apiv2.views.download_file",
                return_value=("ok", {"task_ids": [123], "errors": []}),
            ),
        ):
            response = self.client.post(
                "/apiv2/tasks/create/dlnexec/",
                {
                    "dlnexec": "https://example.com/sample.exe",
                    "machine": "reserved-machine",
                },
            )

        assert response.status_code == 200
        assert response.json()["data"]["task_ids"] == [123]
