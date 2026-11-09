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


@pytest.mark.usefixtures("db", "tmp_cuckoo_root")
class TestYaraUploaderSanitization(SimpleTestCase):
    @staticmethod
    def _build_fake_plyara(parsed_rules):
        def _rebuild_yara_rule(rule):
            meta_lines = []
            for item in rule.get("metadata", []):
                for k, v in item.items():
                    meta_lines.append(f'        {k} = "{v}"')
            meta_block = "\n".join(meta_lines)
            return f"rule {rule['rule_name']} {{\n    meta:\n{meta_block}\n    condition:\n        true\n}}"

        class _FakePlyaraInstance:
            def parse_string(self, _content):
                return [
                    {
                        "rule_name": r["rule_name"],
                        "metadata": [dict(m) for m in r.get("metadata", [])],
                    }
                    for r in parsed_rules
                ]

        return SimpleNamespace(
            Plyara=_FakePlyaraInstance,
            utils=SimpleNamespace(rebuild_yara_rule=_rebuild_yara_rule),
        )

    def _post_rule(self, rule_text: str, upload_name: str = "rule.yar", category: str = "CAPE", **extra):
        uploaded_file = SimpleUploadedFile(
            upload_name,
            rule_text.encode("utf-8"),
            content_type="text/plain",
        )
        return self.client.post(
            "/apiv2/yara_uploader/",
            {"category": category, "file": uploaded_file},
            **extra,
        )

    def test_rejects_invalid_or_non_string_family_metadata(self):
        invalid_families = (
            "../../evil",
            "..\\..\\evil",
            "..",
            ".",
            ".hidden",
            "bad..name",
            123,
            True,
        )
        rule_text = 'rule test_rule { strings: $a = "test" condition: $a }'
        for bad_family in invalid_families:
            with self.subTest(bad_family=bad_family):
                fake_plyara = self._build_fake_plyara(
                    [{"rule_name": "test_rule", "metadata": [{"family": bad_family}]}]
                )
                with (
                    patch("apiv2.views.HAVE_PLYARA", True),
                    patch("apiv2.views.plyara", fake_plyara, create=True),
                    patch.dict("apiv2.views.apiconf.yara_uploader", {"enabled": True, "auth_only": False}),
                    patch("apiv2.views.DIST_ENABLED", False),
                ):
                    response = self._post_rule(rule_text)

                assert response.status_code == 400
                assert response.json()["status"] == "error"
                assert "family" in response.json()["message"].lower()

    def test_non_yar_upload_filename_falls_back_to_family_yar_and_existing_yar_appends(self):
        import tempfile

        rule_text = 'rule test_valid_family { strings: $a = "test" condition: $a }'
        fake_plyara = self._build_fake_plyara(
            [{"rule_name": "test_valid_family", "metadata": [{"family": "TestFamily"}]}]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            dest_dir = tmp_path / "data" / "yara" / "CAPE"
            dest_dir.mkdir(parents=True, exist_ok=True)
            readme = dest_dir / "README.md"
            readme.write_text("do not overwrite", encoding="utf-8")

            with (
                patch("apiv2.views.HAVE_PLYARA", True),
                patch("apiv2.views.plyara", fake_plyara, create=True),
                patch.dict("apiv2.views.apiconf.yara_uploader", {"enabled": True, "auth_only": False}),
                patch("apiv2.views.CUCKOO_ROOT", str(tmp_path)),
                patch("apiv2.views.DIST_ENABLED", False),
            ):
                resp_readme = self._post_rule(rule_text, upload_name="README.md")

            assert resp_readme.status_code == 200
            assert readme.read_text(encoding="utf-8") == "do not overwrite"
            assert (dest_dir / "TestFamily.yar").is_file()

    def test_auth_only_requires_authentication_and_accepts_api_key(self):
        import tempfile

        rule_text = 'rule test_auth_family { strings: $a = "test" condition: $a }'
        fake_plyara = self._build_fake_plyara(
            [{"rule_name": "test_auth_family", "metadata": [{"family": "AuthFamily"}]}]
        )
        fake_user = SimpleNamespace(is_authenticated=True, username="analyst")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            with (
                patch("apiv2.views.HAVE_PLYARA", True),
                patch("apiv2.views.plyara", fake_plyara, create=True),
                patch.dict("apiv2.views.apiconf.yara_uploader", {"enabled": True, "auth_only": True}),
                patch("apiv2.views.CUCKOO_ROOT", str(tmp_path)),
                patch("apiv2.views.DIST_ENABLED", False),
            ):
                unauth_resp = self._post_rule(rule_text)
                assert unauth_resp.status_code == 401

                with patch("apiv2.views.ApiKeyAuthentication") as mock_auth_cls:
                    mock_auth_cls.return_value.authenticate.return_value = (fake_user, "token")
                    auth_resp = self._post_rule(rule_text, HTTP_AUTHORIZATION="Token test-token")

            assert auth_resp.status_code == 200
            saved = (tmp_path / "data" / "yara" / "CAPE" / "AuthFamily.yar").read_text(encoding="utf-8")
            assert "analyst" in saved


@pytest.mark.usefixtures("db", "tmp_cuckoo_root")
class TestTasksIocs(SimpleTestCase):
    def test_tasks_iocs_tolerates_missing_target_file_path_and_guest_paths(self):
        report_buf = {
            "malscore": 5.0,
            "detections": [],
            "info": {"id": 1, "custom": "", "machine": {"manager": "kvm", "label": "win10", "id": 1, "name": "win10"}},
            "target": {"category": "file", "file": {"name": "sample.exe", "sha256": "a" * 64}},
            "network": {},
            "behavior": {"summary": {}, "processtree": []},
            "dropped": [],
        }
        with (
            patch.dict("apiv2.views.apiconf.taskiocs", {"enabled": True}),
            patch.dict("apiv2.views.repconf.mongodb", {"enabled": True}),
            patch("apiv2.views.validate_task", return_value={"error": False, "rtid": 1}),
            patch("apiv2.views.mongo_find_one", return_value=report_buf, create=True),
        ):
            resp = self.client.get("/apiv2/tasks/get/iocs/1/")

        assert resp.status_code == 200
        body = resp.json()
        assert body["error"] is False
        assert body["data"]["target"]["file"] == {"name": "sample.exe", "sha256": "a" * 64}


@pytest.mark.usefixtures("db", "tmp_cuckoo_root")
class TestEncryptedSampleDownload(SimpleTestCase):
    def test_encrypted_sample_download_uses_cape_external_dir(self):
        import subprocess
        import tempfile

        sha256 = "b" * 64
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            sample_path = root / "sample.bin"
            sample_path.write_bytes(b"MZ-encrypted-sample-test")
            ext_dir = root / "cape-external"
            ext_dir.mkdir()

            with (
                patch.dict("apiv2.views.apiconf.sampledl", {"enabled": True}),
                patch("apiv2.views.db.sample_path_by_hash", return_value=[str(sample_path)]),
                patch("apiv2.views.USE_SEVENZIP", False),
                patch("apiv2.views.get_cape_external_dir", return_value=str(ext_dir)),
            ):
                resp = self.client.get(f"/apiv2/files/get/sha256/{sha256}/?encrypted=1")
                assert resp.status_code == 200
                payload = b"".join(resp.streaming_content)
                resp.close()

                expected_zip = ext_dir / f"{sha256}.zip"
                assert expected_zip.is_file()
                assert len(payload) > 0

                # Second call hits cached zip inside cape-external without re-archiving.
                with patch("apiv2.views.pyzipper.AESZipFile", side_effect=AssertionError("unexpected re-zip")):
                    cached_resp = self.client.get(f"/apiv2/files/get/sha256/{sha256}/?encrypted=1")
                    assert cached_resp.status_code == 200
                    cached_payload = b"".join(cached_resp.streaming_content)
                    cached_resp.close()
                assert cached_payload == payload

                # Failed 7z compression cleans up temp zip and does not leave a corrupt cached archive.
                expected_zip.unlink()
                with (
                    patch("apiv2.views.USE_SEVENZIP", True),
                    patch("apiv2.views.subprocess.check_call", side_effect=subprocess.CalledProcessError(1, ["7z"])),
                ):
                    err_resp = self.client.get(f"/apiv2/files/get/sha256/{sha256}/?encrypted=1")
                    assert err_resp.status_code == 200
                    assert err_resp.json()["error"] is True
                assert list(ext_dir.iterdir()) == []

    def test_pcapng_response_uses_cape_external_and_unlinks_on_empty_output(self):
        import tempfile
        from apiv2.views import _pcapng_response

        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            adir = root / "storage" / "analyses" / "99"
            adir.mkdir(parents=True)
            (adir / "dump.pcap").write_bytes(b"pcap")
            ext_dir = root / "cape-external"
            ext_dir.mkdir()

            class _EmptyPcapToNg:
                def __init__(self, *_a):
                    pass

                def generate(self, _out_path):
                    # Leave 0-byte file
                    pass

            with (
                patch("apiv2.views.CUCKOO_ROOT", str(root)),
                patch("apiv2.views.get_cape_external_dir", return_value=str(ext_dir)),
                patch("lib.cuckoo.common.pcap_utils.PcapToNg", _EmptyPcapToNg),
            ):
                resp = _pcapng_response(99)
                assert resp.data["error"] is True
            assert list(ext_dir.iterdir()) == []



