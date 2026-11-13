import hashlib
import os
from unittest.mock import patch

from analysis.views import enabledconf
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase
import pytest
from submission import static_preview
from submission.views import web_conf


@pytest.mark.usefixtures("db", "tmp_cuckoo_root")
class TestStaticPreview(SimpleTestCase):
    def setUp(self):
        self.original_web_auth = getattr(settings, "WEB_AUTHENTICATION", False)
        self.original_mongodb_enabled = enabledconf.get("mongodb", False)
        self.original_ratelimit = getattr(settings, "RATELIMIT_ENABLE", True)
        settings.WEB_AUTHENTICATION = False
        settings.RATELIMIT_ENABLE = False
        enabledconf["mongodb"] = False
        static_preview._STATIC_PREVIEW_CACHE.clear()

    def tearDown(self):
        settings.WEB_AUTHENTICATION = self.original_web_auth
        settings.RATELIMIT_ENABLE = self.original_ratelimit
        enabledconf["mongodb"] = self.original_mongodb_enabled
        static_preview._STATIC_PREVIEW_CACHE.clear()

    def _create_sample_task(self, content: bytes = b"MZ\x90\x00test-sample-payload", filename: str = "sample.exe"):
        import shutil
        import tempfile
        from lib.cuckoo.core.database import Database

        db = Database()
        tmp_root = tempfile.mkdtemp(prefix="cape_static_preview_")
        self.addCleanup(shutil.rmtree, tmp_root, ignore_errors=True)
        binaries_dir = os.path.join(tmp_root, "storage", "binaries")
        os.makedirs(binaries_dir, exist_ok=True)
        tmp_file = os.path.join(tmp_root, filename)
        with open(tmp_file, "wb") as f:
            f.write(content)
        sha256 = hashlib.sha256(content).hexdigest()
        with open(os.path.join(binaries_dir, sha256), "wb") as f:
            f.write(content)

        task_id = db.add_path(file_path=tmp_file)
        task = db.view_task(task_id)
        return db, task, sha256, tmp_file

    def test_get_static_preview_tier1_and_tier2_caching(self):
        _, task, sha256, tmp_file = self._create_sample_task()

        with patch.object(static_preview, "CUCKOO_ROOT", os.path.dirname( tmp_file )):
            # Tier 1: fast path (run_full=False) returns SQL metadata immediately without enrichment
            tier1 = static_preview.get_static_preview(task, run_full=False)
            self.assertIsNotNone(tier1)
            self.assertFalse(tier1["static_enriched"])
            self.assertEqual(tier1["file"]["sha256"], sha256)
            self.assertEqual(tier1["file"]["name"], "sample.exe")

            fake_hit = {
                "name": "TestFamily",
                "meta": {"cape_type": "TestFamily Payload"},
                "strings": [],
                "addresses": {},
            }
            fake_full_info = {
                "name": "sample.exe",
                "size": 27,
                "crc32": "12345678",
                "md5": "a" * 32,
                "sha1": "b" * 40,
                "sha256": sha256,
                "sha512": "c" * 128,
                "ssdeep": "",
                "tlsh": "T1" + "0" * 70,
                "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
                "yara": [{"name": "GenericRule", "meta": {}, "strings": ["$a"]}],
                "cape_yara": [fake_hit],
            }

            with (
                patch.object(static_preview.File, "get_all", return_value=(fake_full_info, [])),
                patch.object(static_preview, "_run_read_only_static_enrichment") as mock_enrich,
                patch.object(
                    static_preview,
                    "static_config_parsers",
                    return_value={"TestFamily": {"C2": ["198.51.100.10:443"]}},
                ) as mock_cfg_parser,
            ):
                # Tier 2: full static enrichment (run_full=True)
                tier2 = static_preview.get_static_preview(task, run_full=True)
                self.assertIsNotNone(tier2)
                self.assertTrue(tier2["static_enriched"])
                self.assertEqual(tier2["file"]["tlsh"], "T1" + "0" * 70)
                self.assertEqual(len(tier2["malware_conf"]), 1)
                self.assertIn("TestFamily", tier2["malware_conf"][0])
                self.assertEqual(tier2["malware_conf"][0]["TestFamily"]["C2"], ["198.51.100.10:443"])
                mock_enrich.assert_called_once()
                mock_cfg_parser.assert_called_once()

            # Subsequent Tier 1 call hits the in-memory cache and returns enriched=True
            cached = static_preview.get_static_preview(task, run_full=False)
            self.assertTrue(cached["static_enriched"])
            self.assertEqual(len(cached["malware_conf"]), 1)

    def test_get_static_preview_returns_none_for_url_task(self):
        from lib.cuckoo.core.database import Database

        db = Database()
        task_id = db.add_url("http://example.com/mal.exe")
        task = db.view_task(task_id)
        self.assertIsNone(static_preview.get_static_preview(task, run_full=False))
        self.assertIsNone(static_preview.get_static_preview(task, run_full=True))

    def test_update_static_preview_service(self):
        sha256 = "f" * 64
        updated = static_preview.update_static_preview_service(sha256, "flare_capa", {"CAPABILITY": ["test"]})
        self.assertEqual(updated["flare_capa"], {"CAPABILITY": ["test"]})

        updated_xlm = static_preview.update_static_preview_service(sha256, "xlsdeobf", ["CELL:A1"])
        self.assertEqual(updated_xlm["office"]["XLMMacroDeobfuscator"], ["CELL:A1"])

    def test_status_view_initial_and_htmx_static_and_poll(self):
        _, task, sha256, tmp_file = self._create_sample_task()
        orig_existent = web_conf.general.get("existent_tasks", False)
        orig_preview_enabled = web_conf.static_preview.get("enabled", False)

        try:
            web_conf.general.existent_tasks = True
            web_conf.static_preview.enabled = True
            fake_prior = [{"info": {"id": 999, "started": "2026-01-01 10:00:00"}, "target": {"file": {"sha256": sha256}}, "malfamily": "TestFamily"}]
            with (
                patch.object(static_preview, "CUCKOO_ROOT", os.path.dirname(tmp_file)),
                patch("submission.views.perform_search", return_value=fake_prior),
            ):
                # 1. Initial GET renders status page with Tier-1 static info, queue position, elapsed timer, existent_tasks, and HTMX ?static=1 trigger
                response = self.client.get(f"/submit/status/{task.id}/")
                self.assertEqual(response.status_code, 200)
                body = response.content.decode()
                self.assertIn('id="auto-redirect-toggle"', body)
                self.assertIn('id="status-card"', body)
                self.assertIn('id="queue-position-badge"', body)
                self.assertIn("Queue #1", body)
                self.assertIn('id="elapsed-time-badge"', body)
                self.assertIn("Existing Analyses for this Sample", body)
                self.assertIn("Task #999", body)
                self.assertIn('id="static-preview-container"', body)
                self.assertIn(f'/submit/status/{task.id}/?static=1', body)
                self.assertIn(sha256, body)

                # 2. HTMX ?static=1 request runs Tier-2 static enrichment and returns _static_preview.html partial
                with patch.object(
                    static_preview,
                    "_extract_static_cape_configs",
                    return_value=[{"TestMalware": {"URL": ["hxxp://bad.example/cfg"]}, "_associated_config_hashes": [{"sha256": sha256}]}],
                ):
                    static_resp = self.client.get(f"/submit/status/{task.id}/?static=1", HTTP_HX_REQUEST="true")
                    self.assertEqual(static_resp.status_code, 200)
                    static_body = static_resp.content.decode()
                    self.assertIn("Malware Configuration (Static)", static_body)
                    self.assertIn("TestMalware Config", static_body)
                    self.assertIn("hxxp://bad.example/cfg", static_body)
                    self.assertIn("Existing Analyses for this Sample", static_body)

                # 3. 5-second HTMX status poll skips get_static_preview
                with patch("submission.static_preview.get_static_preview") as mock_preview:
                    poll_resp = self.client.get(f"/submit/status/{task.id}/", HTTP_HX_REQUEST="true")
                    self.assertEqual(poll_resp.status_code, 200)
                    mock_preview.assert_not_called()
        finally:
            web_conf.general.existent_tasks = orig_existent
            web_conf.static_preview.enabled = orig_preview_enabled

    def test_report_view_redirects_in_progress_task_to_submission_status(self):
        _, task, _, _ = self._create_sample_task()
        self.assertEqual(task.status, "pending")

        response = self.client.get(f"/analysis/{task.id}/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], f"/submit/status/{task.id}/")

    def test_single_task_submission_redirects_directly_to_status(self):
        upload = SimpleUploadedFile("sample.bin", b"MZ\x90\x00single-task")
        with (
            patch("submission.views.process_new_task_files", return_value=([(b"MZ", "/tmp/sample.bin", "a" * 64)], {"errors": [], "task_ids": []})),
            patch("submission.views.download_file", return_value=("ok", {"task_ids": [42], "errors": []})),
        ):
            web_conf.general.existent_tasks = False
            response = self.client.post("/submit/", {"category": "sample", "sample": upload})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response["Location"], "/submit/status/42/")

    def test_get_queue_position_strict_transactions(self):
        from submission.views import _get_queue_position
        from django.test.client import RequestFactory

        _, task1, _, _ = self._create_sample_task(content=b"MZ\x90\x00queue-1", filename="sample1.exe")
        _, task2, _, _ = self._create_sample_task(content=b"MZ\x90\x00queue-2", filename="sample2.exe")

        rf = RequestFactory()
        request = rf.get(f"/submit/status/{task2.id}/")
        request.user = None

        pos = _get_queue_position(request, task2)
        self.assertIsNotNone(pos)
        self.assertGreaterEqual(pos, 2)


    def test_status_view_interactive_guacamole_states(self):
        from lib.cuckoo.core.data.task import Task

        db, task, _, tmp_file = self._create_sample_task()
        orig_guac = web_conf.guacamole.enabled
        try:
            web_conf.guacamole.enabled = True
            with db.session.begin():
                t = db.session.get(Task, task.id)
                t.options = "interactive=1,nohuman=yes"
                t.machine = "win10_1"
                t.status = "pending"

            fake_machine = type("M", (), {"label": "win10_1", "ip": "192.168.122.10"})()
            with (
                patch.object(static_preview, "CUCKOO_ROOT", os.path.dirname(tmp_file)),
                patch("submission.views.db.view_machine_by_label", return_value=fake_machine),
            ):
                # 1. Pending state: shows waiting banner & Start Session link, does NOT mint session_data yet
                pending_resp = self.client.get(f"/submit/status/{task.id}/")
                pending_body = pending_resp.content.decode()
                self.assertIn("Interactive VM Session Enabled", pending_body)
                self.assertIn(f"/submit/remote_session/{task.id}/", pending_body)
                self.assertIn('id="auto-guac-toggle"', pending_body)
                self.assertNotIn("Interactive VM Session Ready", pending_body)

                # 2. Running state: mints session_data and shows Open Console button
                with db.session.begin():
                    t = db.session.get(Task, task.id)
                    t.status = "running"

                running_resp = self.client.get(f"/submit/status/{task.id}/")
                running_body = running_resp.content.decode()
                self.assertIn("Interactive VM Session Ready", running_body)
                self.assertIn(f"/guac/{task.id}/", running_body)

                # 3. Completed (processing) state: hides both waiting and ready Guac banners
                with db.session.begin():
                    t = db.session.get(Task, task.id)
                    t.status = "completed"

                proc_resp = self.client.get(f"/submit/status/{task.id}/")
                proc_body = proc_resp.content.decode()
                self.assertNotIn("Interactive VM Session Ready", proc_body)
                self.assertNotIn("Interactive VM Session Enabled", proc_body)
        finally:
            web_conf.guacamole.enabled = orig_guac

    def test_mongodb_persistence_and_cross_worker_sharing(self):
        _, task, sha256, tmp_file = self._create_sample_task()
        orig_mongo = static_preview.reporting_conf.mongodb.enabled
        persisted_docs = {}

        def fake_update_one(collection, query, update, **kwargs):
            self.assertEqual(collection, "files")
            self.assertTrue(kwargs.get("upsert"))
            doc = dict(update.get("$set", {}))
            if "$addToSet" in update and "_task_ids" in update["$addToSet"]:
                doc.setdefault("_task_ids", []).append(update["$addToSet"]["_task_ids"])
            persisted_docs[query["_id"]] = doc

        def fake_find_one(collection, query, **kwargs):
            key = query.get("_id") or query.get("sha256")
            return persisted_docs.get(key)

        try:
            static_preview.reporting_conf.mongodb.enabled = True
            fake_hit = {"name": "TestFamily", "meta": {"cape_type": "TestFamily Payload"}, "strings": [], "addresses": {}}
            fake_full_info = {
                "name": "sample.exe",
                "size": 27,
                "sha256": sha256,
                "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
                "yara": [],
                "cape_yara": [fake_hit],
            }
            with (
                patch.object(static_preview, "CUCKOO_ROOT", os.path.dirname(tmp_file)),
                patch.object(static_preview, "mongo_update_one", side_effect=fake_update_one) as mock_update,
                patch.object(static_preview, "mongo_find_one", side_effect=fake_find_one),
                patch.object(static_preview.File, "get_all", return_value=(fake_full_info, [])) as mock_get_all,
                patch.object(static_preview, "_run_read_only_static_enrichment"),
                patch.object(
                    static_preview,
                    "static_config_parsers",
                    return_value={"TestFamily": {"C2": ["198.51.100.10:443"]}},
                ) as mock_cfg,
            ):
                # Worker 1 computes full static preview and persists to MongoDB
                res1 = static_preview.get_static_preview(task, run_full=True)
                self.assertTrue(res1["static_enriched"])
                mock_update.assert_called_once()
                self.assertIn(sha256, persisted_docs)
                self.assertIn(task.id, persisted_docs[sha256]["_task_ids"])
                self.assertTrue(persisted_docs[sha256]["static_preview_enriched"])
                mock_get_all.assert_called_once()
                mock_cfg.assert_called_once()

                # Simulate Worker 2 (empty in-memory cache) serving a shared link (run_full=False)
                static_preview._STATIC_PREVIEW_CACHE.clear()
                mock_get_all.reset_mock()
                mock_cfg.reset_mock()

                res2 = static_preview.get_static_preview(task, run_full=False)
                self.assertTrue(res2["static_enriched"])
                self.assertEqual(res2["malware_conf"][0]["TestFamily"]["C2"], ["198.51.100.10:443"])
                mock_get_all.assert_not_called()
                mock_cfg.assert_not_called()
        finally:
            static_preview.reporting_conf.mongodb.enabled = orig_mongo

    def test_cape_process_file_reuses_persisted_static_preview(self):
        from modules.processing import CAPE as cape_mod

        _, task, sha256, tmp_file = self._create_sample_task()
        orig_mongo = cape_mod.reporting_conf.mongodb.enabled
        orig_cache = cape_mod.processing_conf.CAPE.file_cache

        persisted_doc = {
            "_id": sha256,
            "_task_ids": [task.id],
            "sha256": sha256,
            "md5": "a" * 32,
            "sha1": "b" * 40,
            "sha512": "c" * 128,
            "sha3_384": "d" * 96,
            "size": 27,
            "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
            "pe": {"imphash": "11223344"},
            "yara": [],
            "cape_yara": [{"name": "TestFamily", "meta": {"cape_type": "TestFamily Payload"}}],
            "yara_hash": cape_mod.File.yara_rules_hash,
            "static_preview_enriched": True,
            "static_preview_malware_conf": [
                {
                    "TestFamily": {"C2": ["198.51.100.10:443"]},
                    "_associated_config_hashes": [{"sha256": sha256}],
                }
            ],
        }

        try:
            cape_mod.reporting_conf.mongodb.enabled = True
            cape_mod.processing_conf.CAPE.file_cache = False

            processor = cape_mod.CAPE()
            processor.task = {"id": task.id, "target": tmp_file, "options": "", "package": "exe"}
            processor.options = cape_mod.processing_conf.CAPE
            processor.results = {"statistics": {"processing": []}}
            processor.cape = {"payloads": [], "configs": []}
            processor.self_extracted = ""

            with (
                patch.object(cape_mod, "mongo_find_one", return_value=dict(persisted_doc)),
                patch.object(cape_mod.File, "get_all") as mock_get_all,
                patch.object(cape_mod, "static_file_info") as mock_static_info,
                patch.object(cape_mod, "static_config_parsers") as mock_cfg_parser,
            ):
                processor.process_file(
                    tmp_file, False, {}, category="file", duplicated={"sha256": set(), "TLSH": set()}
                )
                file_info = processor.results["target"]["file"]
                # File.get_all and static_config_parsers should both be skipped because MongoDB had the preview
                mock_get_all.assert_not_called()
                mock_cfg_parser.assert_not_called()
                mock_static_info.assert_called_once()
                self.assertEqual(file_info["pe"]["imphash"], "11223344")
                self.assertNotIn("static_preview_malware_conf", file_info)
                self.assertNotIn("static_preview_enriched", file_info)
                self.assertNotIn("_task_ids", file_info)
                self.assertEqual(len(processor.cape["configs"]), 1)
                self.assertEqual(processor.cape["configs"][0]["TestFamily"]["C2"], ["198.51.100.10:443"])
        finally:
            cape_mod.reporting_conf.mongodb.enabled = orig_mongo
            cape_mod.processing_conf.CAPE.file_cache = orig_cache

    def test_cape_process_file_runs_static_when_file_cache_disabled_and_resolves_selfextract_fallback(self):
        from modules.processing import CAPE as cape_mod

        _, task, sha256, tmp_file = self._create_sample_task()
        orig_mongo = cape_mod.reporting_conf.mongodb.enabled
        orig_cache = cape_mod.processing_conf.CAPE.file_cache

        child_bytes = b"MZ_child_payload"
        child_sha = hashlib.sha256(child_bytes).hexdigest()
        storage_child = os.path.join(
            os.path.dirname(tmp_file), "storage", "files", child_sha[:2], child_sha[2:4], child_sha
        )
        os.makedirs(os.path.dirname(storage_child), exist_ok=True)
        with open(storage_child, "wb") as fh:
            fh.write(child_bytes)

        options_hash = hashlib.sha256(b"{}").hexdigest()
        persisted_doc = {
            "_id": sha256,
            "sha256": sha256,
            "size": 27,
            "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
            "yara": [],
            "cape_yara": [],
            "yara_hash": cape_mod.File.yara_rules_hash,
            "options_hash": options_hash,
            "static_preview_enriched": True,
            "selfextract": {
                "Unpacker": {
                    "extracted_files": [
                        {
                            "sha256": child_sha,
                            "path": "/nonexistent/storage/analyses/1/selfextracted/" + child_sha,
                            "cape_yara": [{"name": "ChildFamily", "meta": {"cape_type": "ChildFamily Payload"}}],
                        }
                    ]
                }
            },
        }

        try:
            cape_mod.reporting_conf.mongodb.enabled = True
            cape_mod.processing_conf.CAPE.file_cache = False

            processor = cape_mod.CAPE()
            processor.task = {"id": task.id + 100, "target": tmp_file, "options": "", "package": "exe"}
            processor.options = cape_mod.processing_conf.CAPE
            processor.results = {"statistics": {"processing": []}}
            processor.cape = {"payloads": [], "configs": []}
            processor.self_extracted = ""

            with (
                patch.object(cape_mod, "mongo_find_one", return_value=dict(persisted_doc)),
                patch.object(cape_mod, "get_files_storage_path", return_value=storage_child),
                patch.object(cape_mod, "static_file_info") as mock_static_info,
                patch.object(
                    cape_mod,
                    "static_config_parsers",
                    return_value={"ChildFamily": {"C2": ["192.0.2.1:80"]}},
                ) as mock_cfg_parser,
            ):
                processor.process_file(
                    tmp_file, False, {}, category="file", duplicated={"sha256": set(), "TLSH": set()}
                )
                # Even though options_hash and yara_hash match, file_cache=False must still run static_file_info
                mock_static_info.assert_called_once()
                # And stale selfextract path must fall back to get_files_storage_path without FileNotFoundError
                mock_cfg_parser.assert_called_once()
                self.assertEqual(processor.cape["configs"][0]["ChildFamily"]["C2"], ["192.0.2.1:80"])
        finally:
            cape_mod.reporting_conf.mongodb.enabled = orig_mongo
            cape_mod.processing_conf.CAPE.file_cache = orig_cache

    def test_on_demand_rejects_mismatched_sha256_for_unreported_task(self):
        """on_demand must not fall back to storage/binaries/<sha256> when sha256 does not match the task sample."""
        import analysis.views as analysis_views

        _, task, _, tmp_file = self._create_sample_task(b"MZ" + b"\x42" * 64, filename="task_sample.exe")
        other_bytes = b"MZ" + b"\x41" * 64
        other_sha256 = hashlib.sha256(other_bytes).hexdigest()
        other_file = os.path.join(os.path.dirname(tmp_file), "storage", "binaries", other_sha256)
        with open(other_file, "wb") as f:
            f.write(other_bytes)

        orig_strings = analysis_views.processing_cfg.strings.on_demand
        analysis_views.processing_cfg.strings.on_demand = True
        try:
            with (
                patch.object(analysis_views, "CUCKOO_ROOT", os.path.dirname(tmp_file)),
                patch.object(analysis_views, "ANALYSIS_BASE_PATH", os.path.dirname(tmp_file)),
                patch.object(analysis_views, "_path_safe", return_value=True),
                patch.object(
                    analysis_views,
                    "path_exists",
                    side_effect=lambda p: p.endswith(os.path.join("storage", "binaries", other_sha256)),
                ),
                patch.object(analysis_views, "extract_strings", return_value=["secret_string"], create=True) as mock_strings,
            ):
                resp = self.client.get(
                    f"/analysis/on_demand/strings/{task.id}/static/{other_sha256}/",
                    HTTP_HX_REQUEST="true",
                )
                self.assertEqual(resp.status_code, 404)
                mock_strings.assert_not_called()
        finally:
            analysis_views.processing_cfg.strings.on_demand = orig_strings

    def test_shellcode_on_demand_kwargs_and_preview_package(self):
        """Shellcode on-demand resolves arch/entry/va hints and tolerates missing SQL tasks."""
        import analysis.views as analysis_views

        sample_bytes = b"\x90" * 64
        db, task, sha256, tmp_file = self._create_sample_task(sample_bytes, filename="sc.bin")
        with db.session.begin():
            t = db.view_task(task.id)
            t.package = "shellcode_x64"
            t.options = "offset=0x100"
        task = db.view_task(task.id)

        preview = static_preview.get_static_preview(task, run_full=False)
        self.assertEqual(preview["analysis"]["info"]["package"], "shellcode_x64")

        self.assertEqual(
            analysis_views._shellcode_on_demand_kwargs(str(task.id), "static", sha256),
            {"arch": "x64", "entry": "0x100"},
        )
        self.assertIsNone(analysis_views._shellcode_on_demand_kwargs(str(task.id), "static", "00" * 32))

        # Distributed / cleaned SQL task: db.view_task returns None, falls back to MongoDB without AttributeError
        mongo_doc = {
            "info": {"package": "shellcode", "options": "offset=0x40"},
            "target": {"file": {"sha256": sha256}},
            "CAPE": {"payloads": [{"sha256": sha256, "cape_type_code": 9, "virtual_address": "0x00790000"}]},
        }
        with (
            patch.object(analysis_views.db, "view_task", return_value=None),
            patch.dict(analysis_views.enabledconf, {"mongodb": True}),
            patch.object(analysis_views, "mongo_find_one", return_value=mongo_doc, create=True),
            patch.object(analysis_views, "ANALYSIS_BASE_PATH", os.path.dirname(tmp_file)),
        ):
            self.assertEqual(analysis_views.get_task_package(999999), "")
            self.assertEqual(
                analysis_views._shellcode_on_demand_kwargs("999999", "target.file", sha256),
                {"arch": "x86", "entry": "0x40"},
            )
            self.assertEqual(
                analysis_views._shellcode_on_demand_kwargs("999999", "CAPE", sha256),
                {"va": "0x00790000"},
            )

    def test_static_preview_auto_enriches_shellcode_package(self):
        """When static_shellcode_check is enabled without on_demand, shellcode packages are enriched in preview."""
        import lib.cuckoo.common.integrations.shellcode_utils as sc_utils

        if not sc_utils.HAVE_SHELLCODE_CHECK:
            self.skipTest("Capstone unavailable")

        msf_x64 = bytes.fromhex(
            "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c61"
            "7c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0"
            "e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b"
            "0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d49"
            "c7c63332000041564989e64c89f141ba4c772607ffd54831c9ba0010000041b80030000041b94000000041ba58a453e5ffd5c3"
        )
        db, task, sha256, tmp_file = self._create_sample_task(b"\x90" * 0x20 + msf_x64, filename="stager.bin")
        with db.session.begin():
            t = db.view_task(task.id)
            t.package = "shellcode_x64"
            t.options = "offset=0x20"
        task = db.view_task(task.id)

        sc_section = {"enabled": True, "on_demand": False, "submitted_shellcode": True, "shellcode_depth": 65536}
        with (
            patch.object(static_preview, "CUCKOO_ROOT", os.path.dirname(tmp_file)),
            patch.object(static_preview.processing_conf, "static_shellcode_check", sc_section, create=True),
        ):
            preview = static_preview.get_static_preview(task, run_full=True)
            sc = preview["file"].get("static_shellcode_check")
            self.assertIsNotNone(sc)
            self.assertEqual(sc["verdict"], "shellcode")
            self.assertEqual(sc["arch"], "x64")
            self.assertEqual(sc["entry"], "0x20")
            self.assertNotIn("_payloads", sc)

    def test_shellcode_templates_render_encoder_capabilities_and_links(self):
        """Verify _file_info.html and _shellcode_check.html improvements for shellcode display."""
        from django.template.loader import render_to_string

        parent_sha = "11" * 32
        child_sha = "22" * 32
        sc_data = {
            "verdict": "shellcode",
            "arch": "x86",
            "pic": "yes",
            "score": 12,
            "scanned": 512,
            "size": 512,
            "time_ms": 1.2,
            "capabilities": {"raw_socket": ["WSAStartup", "connect"]},
            "encoder": {
                "name": "x86/shikata_ga_nai x3",
                "arch": "x86",
                "layers": 3,
                "payload": "x86 code",
                "payload_size": 310,
                "payload_indicators": "peb_walk, api_hash_loop",
            },
            "indicators": [
                {
                    "name": f"ind_{idx}",
                    "group": "decoders",
                    "confidence": "high",
                    "description": f"desc {idx}",
                    "offsets": [f"0x{idx:x}"],
                }
                for idx in range(7)
            ]
            + [
                {
                    "name": "framework_layout",
                    "group": "framework",
                    "confidence": "high",
                    "description": "Donut layout",
                    "offsets": ["0x0"],
                }
            ],
            "extracted": [
                {
                    "sha256": child_sha,
                    "size": 4096,
                    "cape_type": "Extracted Shellcode Payload",
                    "framework": None,
                    "offset": "0x1b",
                    "description": "x86/shikata_ga_nai x3 decoded x86 code",
                }
            ],
            "evidence": [{"offset": "0x0", "indicator": "framework_layout", "insn": "Donut"}],
        }
        html = render_to_string(
            "analysis/generic/_file_info.html",
            {
                "file": {
                    "sha256": parent_sha,
                    "name": "payload.bin",
                    "size": 512,
                    "extracted_from": "00" * 32,
                    "static_shellcode_check": sc_data,
                },
                "tab_name": "CAPE",
                "id": 42,
                "config": {"static_shellcode_check": True},
                "on_demand": {"static_shellcode_check": False},
                "graphs": {"bingraph": {"enabled": False, "content": {}}, "vba2graph": {"enabled": False, "content": {}}},
                "analysis": {"info": {"id": 42, "package": "exe"}, "target": {"file": {"sha256": "ff" * 32}}},
                "expand_service": "static_shellcode_check",
            },
        )
        self.assertIn("encoder: x86/shikata_ga_nai x3", html)
        self.assertIn("peb_walk, api_hash_loop", html)
        self.assertIn("(WSAStartup, connect)", html)
        self.assertIn("+2 more", html)
        self.assertIn("1 payload extracted", html)
        self.assertIn(f'href="#file-info-{"00" * 32}"', html)
        self.assertIn(f'href="#file-info-{child_sha}"', html)
        self.assertNotIn(f'href="#sc-{parent_sha}-framework_layout-0x0"', html)
        self.assertNotIn("Where it matched", html)
        self.assertIn(f'class="collapse show mb-3" id="shellcode_check_{parent_sha}"', html)

        # Derived shellcode payload (cape_type_code == 8197 / 0x2005) gets the on-demand button
        ondemand_html = render_to_string(
            "analysis/generic/_file_info.html",
            {
                "file": {"sha256": child_sha, "name": "derived.bin", "size": 256, "cape_type_code": 8197},
                "tab_name": "CAPE",
                "id": 42,
                "config": {"static_shellcode_check": True},
                "on_demand": {"static_shellcode_check": True},
                "graphs": {"bingraph": {"enabled": False, "content": {}}, "vba2graph": {"enabled": False, "content": {}}},
                "analysis": {"info": {"id": 42, "package": "exe"}, "target": {"file": {"sha256": "ff" * 32}}},
            },
        )
        self.assertIn("Extract: Shellcode Analysis", ondemand_html)

    def test_static_preview_web_conf_enabled_on_demand_and_disabled(self):
        _, task, sha256, tmp_file = self._create_sample_task()
        orig_enabled = web_conf.static_preview.get("enabled", False)
        orig_on_demand = web_conf.static_preview.get("on_demand", True)
        try:
            # Verify default config values are disabled for existent_tasks and static_preview.enabled
            self.assertFalse(bool(web_conf.general.get("existent_tasks", False)))
            self.assertFalse(bool(orig_enabled))
            with patch.object(static_preview, "CUCKOO_ROOT", os.path.dirname(tmp_file)):
                # 1. enabled = False, on_demand = True -> does not auto-load static preview on initial GET, renders Load button
                web_conf.static_preview.enabled = False
                web_conf.static_preview.on_demand = True
                with patch("submission.static_preview.get_static_preview") as mock_get_preview:
                    resp = self.client.get(f"/submit/status/{task.id}/")
                    self.assertEqual(resp.status_code, 200)
                    body = resp.content.decode()
                    mock_get_preview.assert_not_called()
                    self.assertIn('id="load-static-preview-btn"', body)
                    self.assertIn("Load Static Analysis Preview", body)
                    self.assertNotIn('hx-trigger="load"', body)

                # On-demand ?static=1 request succeeds when on_demand = True
                with patch.object(
                    static_preview,
                    "_extract_static_cape_configs",
                    return_value=[{"TestMalware": {"URL": ["hxxp://bad.example/cfg"]}, "_associated_config_hashes": [{"sha256": sha256}]}],
                ):
                    on_demand_resp = self.client.get(f"/submit/status/{task.id}/?static=1", HTTP_HX_REQUEST="true")
                    self.assertEqual(on_demand_resp.status_code, 200)
                    self.assertIn("Malware Configuration (Static)", on_demand_resp.content.decode())

                # 2. enabled = False, on_demand = False -> hides static preview container and rejects ?static=1
                web_conf.static_preview.enabled = False
                web_conf.static_preview.on_demand = False
                resp_disabled = self.client.get(f"/submit/status/{task.id}/")
                self.assertEqual(resp_disabled.status_code, 200)
                disabled_body = resp_disabled.content.decode()
                self.assertNotIn('id="static-preview-container"', disabled_body)
                self.assertNotIn('id="load-static-preview-btn"', disabled_body)

                forbidden_resp = self.client.get(f"/submit/status/{task.id}/?static=1", HTTP_HX_REQUEST="true")
                self.assertEqual(forbidden_resp.status_code, 403)
        finally:
            web_conf.static_preview.enabled = orig_enabled
            web_conf.static_preview.on_demand = orig_on_demand

    def test_stop_pending_task_from_status_page_initializes_storage_and_completes(self):
        import lib.cuckoo.common.constants as cuckoo_constants
        from lib.cuckoo.core.data.task import TASK_COMPLETED

        db, task, sha256, tmp_file = self._create_sample_task()
        tmp_root = os.path.dirname(tmp_file)

        with (
            patch.object(static_preview, "CUCKOO_ROOT", tmp_root),
            patch.object(cuckoo_constants, "CUCKOO_ROOT", tmp_root),
        ):
            # Initial status page shows Stop Dynamic Analysis button
            get_resp = self.client.get(f"/submit/status/{task.id}/")
            self.assertEqual(get_resp.status_code, 200)
            self.assertIn('id="stop-analysis-btn"', get_resp.content.decode())

            # POST action=stop transitions pending task to completed ("processing" in UI) and prepares storage/analyses/<id>
            post_resp = self.client.post(f"/submit/status/{task.id}/", {"action": "stop"}, HTTP_HX_REQUEST="true")
            self.assertEqual(post_resp.status_code, 200)
            post_body = post_resp.content.decode()
            self.assertIn("PROCESSING", post_body)
            self.assertNotIn('id="stop-analysis-btn"', post_body)

            updated_task = db.view_task(task.id)
            self.assertEqual(updated_task.status, TASK_COMPLETED)
            self.assertIsNotNone(updated_task.started_on)
            self.assertIsNotNone(updated_task.completed_on)

            analysis_dir = os.path.join(tmp_root, "storage", "analyses", str(task.id))
            self.assertTrue(os.path.isdir(analysis_dir))
            self.assertTrue(os.path.isdir(os.path.join(analysis_dir, "logs")))
            self.assertTrue(os.path.isdir(os.path.join(analysis_dir, "files")))
            self.assertTrue(os.path.lexists(os.path.join(analysis_dir, "binary")))

    def test_stop_running_task_from_status_page_and_api_sets_guest_stopping(self):
        from lib.cuckoo.core.data.guests import Guest
        from lib.cuckoo.core.data.task import TASK_RUNNING, Task

        db, task, sha256, tmp_file = self._create_sample_task()
        with db.session.begin():
            t = db.session.get(Task, task.id)
            t.status = TASK_RUNNING
            guest = Guest("win10_1", "win10_1", "windows", "KVM", task.id)
            guest.status = "running"
            db.session.add(guest)

        with patch.object(static_preview, "CUCKOO_ROOT", os.path.dirname(tmp_file)):
            # 1. Static preview config card renders "Stop VM & Finalize Report" button while task is running
            with patch.object(
                static_preview,
                "_extract_static_cape_configs",
                return_value=[{"TestMalware": {"URL": ["hxxp://bad.example/cfg"]}, "_associated_config_hashes": [{"sha256": sha256}]}],
            ):
                static_resp = self.client.get(f"/submit/status/{task.id}/?static=1", HTTP_HX_REQUEST="true")
                self.assertEqual(static_resp.status_code, 200)
                self.assertIn('id="stop-analysis-config-btn"', static_resp.content.decode())

            # 2. POST /submit/status/<id>/ sets guest status to "stopping" and displays Stopping VM badge
            post_resp = self.client.post(f"/submit/status/{task.id}/", {"action": "stop"}, HTTP_HX_REQUEST="true")
            self.assertEqual(post_resp.status_code, 200)
            self.assertIn("Stopping VM...", post_resp.content.decode())
            self.assertEqual(db.guest_get_status(task.id), "stopping")

            # Reset guest status to "running" and test POST /apiv2/tasks/status/<id>/ with status="stop"
            db.guest_set_status(task.id, "running")
            api_resp = self.client.post(
                f"/apiv2/tasks/status/{task.id}/",
                data='{"status": "stop"}',
                content_type="application/json",
            )
            self.assertEqual(api_resp.status_code, 200)
            api_json = api_resp.json()
            self.assertFalse(api_json["error"])
            self.assertEqual(api_json["data"], "stopping")
            self.assertEqual(db.guest_get_status(task.id), "stopping")

    def test_tenancy_middleware_requires_manage_rights_on_status_stop_post(self):
        import lib.tenancy.middleware as mw_mod
        from lib.tenancy.policy import TENANT, ResourceScope, ViewerContext
        from submission.views import status as status_view

        scope = ResourceScope(owner_id=7, tenant_id=1, visibility=TENANT)
        owner = ViewerContext(user_id=7, tenant_id=1, is_authenticated=True, tenant_ids=(1,))
        peer = ViewerContext(user_id=9, tenant_id=1, is_authenticated=True, tenant_ids=(1,))

        def make_mw(viewer):
            return mw_mod.TenancyMiddleware(
                lambda r: None,
                viewer_resolver=lambda _u: viewer,
                task_scope_resolver=lambda _tid: scope,
            )

        get_req = type("Req", (), {"path": "/submit/status/42/", "path_info": "/submit/status/42/", "method": "GET", "user": None, "viewer": None, "entitlements": None, "POST": {}, "META": {}})()
        post_req = type("Req", (), {"path": "/submit/status/42/", "path_info": "/submit/status/42/", "method": "POST", "user": None, "viewer": None, "entitlements": None, "POST": {"action": "stop"}, "META": {}})()

        # Peer in same tenant can GET status page, but cannot POST stop action
        self.assertIsNone(make_mw(peer).process_view(get_req, status_view, (), {"task_id": 42}))
        peer_post_res = make_mw(peer).process_view(post_req, status_view, (), {"task_id": 42})
        self.assertIsNotNone(peer_post_res)
        self.assertEqual(getattr(peer_post_res, "status_code", None), 404)

        # Task owner can POST stop action (and middleware does not misclassify it as a file submission POST)
        post_req.viewer = None
        post_req.entitlements = None
        self.assertFalse(mw_mod._is_submission_post(post_req, status_view))
        self.assertIsNone(make_mw(owner).process_view(post_req, status_view, (), {"task_id": 42}))

    def test_multi_file_generic_templates_unique_dom_ids_and_pe_fields(self):
        """Rendering multiple files via analysis/CAPE/index.html produces unique DOM IDs and renders all PE header fields."""
        from collections import Counter
        import re
        from django.template.loader import render_to_string

        sha_one = "aa" * 32
        sha_two = "bb" * 32

        def make_file(sha256, name, headerless_paged=False):
            pe_data = {
                "imagebase": "0x00400000",
                "entrypoint": "0x00431c90",
                "ep_bytes": "55 8b ec 6a ff 68 88 18",
                "machine_type": "0x014c (IMAGE_FILE_MACHINE_I386)",
                "subsystem": "0x0002 (IMAGE_SUBSYSTEM_WINDOWS_GUI)",
                "osversion": "4.0",
                "timestamp": "1970-01-01 00:00:00",
                "reported_checksum": "0x00000000",
                "actual_checksum": "0x000eddd2",
                "imphash": "" if headerless_paged else "11223344556677889900aabbccddeeff",
                "icon": None,
                "icon_fuzzy": None,
                "icon_dhash": None,
                "exported_dll_name": None if headerless_paged else "sample.dll",
                "overlay": None if headerless_paged else {"offset": "0x000e7200", "size": "0x00000400"},
                "sections": [
                    {
                        "name": ".text",
                        "raw_address": "0x00001000",
                        "virtual_address": "0x00001000",
                        "virtual_size": "0x00048000",
                        "size_of_data": "0x00048000",
                        "characteristics": "IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ",
                        "characteristics_raw": "0x60000020",
                        "entropy": "6.51",
                    }
                ],
                "resources": []
                if headerless_paged
                else [
                    {
                        "name": "RT_MANIFEST",
                        "offset": "0x00049000",
                        "size": "0x00000200",
                        "language": "LANG_ENGLISH",
                        "sublanguage": "SUBLANG_ENGLISH_US",
                        "filetype": "XML 1.0 document text",
                        "entropy": "4.12",
                    }
                ],
                "versioninfo": []
                if headerless_paged
                else [{"name": "FileDescription", "value": "Test Binary"}],
                "imports": {}
                if headerless_paged
                else {
                    "KERNEL32": {
                        "dll": "KERNEL32.dll",
                        "imports": [{"address": "0x00401000", "name": "VirtualAlloc"}],
                    }
                },
                "exports": []
                if headerless_paged
                else [{"ordinal": 1, "address": "0x00402000", "name": "ExportedFunc"}],
                "digital_signers": []
                if headerless_paged
                else [
                    {
                        "md5_fingerprint": "11" * 16,
                        "sha1_fingerprint": "22" * 20,
                        "sha256_fingerprint": "33" * 32,
                        "serial_number": "01",
                        "common_name": "Test Signer",
                        "country_name": "US",
                        "locality_name": "TestCity",
                        "organization_name": "TestOrg",
                        "organizational_unit_name": "TestUnit",
                        "email_address": "test@example.com",
                        "not_before": "2026-01-01",
                        "not_after": "2027-01-01",
                        "extensions": {"authorityKeyIdentifier": "keyid:00"},
                    }
                ],
                "guest_signers": {},
            }
            return {
                "sha256": sha256,
                "md5": sha256[:32],
                "sha1": sha256[:40],
                "sha512": sha256 * 2,
                "crc32": "DEADBEEF",
                "name": name,
                "size": 946688,
                "type": "PE32 executable (GUI) Intel 80386, for MS Windows, 4 sections",
                "pe": pe_data,
                "yara": [
                    {
                        "name": "RuleOne",
                        "meta": {"description": "Test YARA rule"},
                        "strings": ["0x100 $s1: test"],
                    }
                ],
                "cape_yara": [
                    {
                        "name": "FamilyRule",
                        "meta": {"cape_type": "Test Payload", "description": "CAPE YARA rule"},
                        "strings": ["0x200 $c1: payload"],
                    }
                ],
                "virustotal": {
                    "summary": {"detection_ratio": "12/72", "permalink": "https://www.virustotal.com/gui/file/" + sha256},
                    "scans": {"EngineA": {"detected": True, "result": "Win32.Test"}},
                },
                "selfextract": {
                    "UnpackerTool": {
                        "extracted_files": [
                            {
                                "name": "inner.bin",
                                "size": 1024,
                                "type": "data",
                                "crc32": "12345678",
                                "md5": "44" * 16,
                                "sha1": "55" * 20,
                                "sha256": hashlib.sha256(sha256.encode()).hexdigest(),
                                "sha512": "77" * 64,
                            }
                        ]
                    }
                },
                "dotnet": {"typerefs": [{"assembly": "mscorlib", "name": "System.Object"}]},
                "floss": {" static_strings": ["floss_str"]},
                "java": {"decompiled": "class Test {}"},
                "lnk": {"flags": ["HasLinkTargetIDList"], "header": {"guid": "00"}},
                "msi": {"SummaryInfo": {"Title": "Test MSI"}},
                "rdp": {"full address": {"type": "s", "value": "192.0.2.10"}},
                "office": {
                    "XLMMacroDeobfuscator": ["CELL:A1"],
                    "Macro": {
                        "Info": {"Analysis": {"Suspicious": [("AutoOpen", "Runs on open")]}},
                        "Code": {"Doc1": [("Module1.bas", "Sub AutoOpen()\nEnd Sub")]},
                    },
                },
                "pdf": {"JSStreams": [{"Name": "Obj 1", "Orig": "app.alert(1);"}]},
            }

        file_one = make_file(sha_one, "full_pe.exe", headerless_paged=False)
        file_two = make_file(sha_two, "paged_pe.bin", headerless_paged=True)

        html = render_to_string(
            "analysis/CAPE/index.html",
            {
                "CAPE": {"payloads": [file_one, file_two]},
                "tab_name": "CAPE",
                "analysis": {
                    "info": {"id": 42, "package": "exe", "category": "file"},
                    "target": {"file": {"sha256": "ff" * 32}},
                    "CAPE": {"payloads": [file_one, file_two]},
                },
                "id": 42,
                "config": {
                    "pe": True,
                    "yara_detail": True,
                    "dotnet": True,
                    "floss": True,
                    "java": True,
                    "lnk": True,
                    "msi": True,
                    "rdp": True,
                    "xlsdeobf": True,
                    "vba2graph": False,
                    "bingraph": False,
                },
                "on_demand": {},
                "graphs": {
                    "bingraph": {"enabled": False, "content": {}},
                    "vba2graph": {"enabled": False, "content": {}},
                },
            },
        )

        # 1. Every DOM id attribute across multiple rendered files must be unique
        ids = re.findall(r'\bid="([^"]+)"', html)
        duplicates = {k: v for k, v in Counter(ids).items() if v > 1}
        self.assertEqual(duplicates, {}, f"Duplicate DOM IDs found across multi-file render: {duplicates}")

        # 2. Every Bootstrap collapse/accordion target and parent selector must reference an existing ID in the document
        id_set = set(ids)
        for attr in ("data-bs-target", "data-bs-parent"):
            for ref in re.findall(rf'\b{attr}="#([^"]+)"', html):
                self.assertIn(ref, id_set, f"{attr}=#{ref} does not match any element id in rendered HTML")

        # 3. Verify newly surfaced PE header fields and per-SHA256 accordion IDs for both standard and paged PE files
        self.assertIn("0x014c (IMAGE_FILE_MACHINE_I386)", html)
        self.assertIn("55 8b ec 6a ff 68 88 18", html)
        self.assertIn("0x00000000 (actual: 0x000eddd2)", html)
        self.assertIn("sample.dll", html)
        self.assertIn("0x000e7200 (size: 0x00000400)", html)
        for sha in (sha_one, sha_two):
            self.assertIn(f'id="peDetailsAccordion_{sha}"', html)
            self.assertIn(f'id="collapseSections_{sha}"', html)
            self.assertIn(f'id="yaraAccordion_{sha}"', html)
            self.assertIn(f'id="capeYaraAccordion_{sha}"', html)
            self.assertIn(f'id="virustotal_binary_{sha}"', html)







