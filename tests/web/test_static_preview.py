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
        from lib.cuckoo.common.constants import CUCKOO_ROOT
        from lib.cuckoo.core.database import Database

        db = Database()
        binaries_dir = os.path.join(CUCKOO_ROOT, "storage", "binaries")
        os.makedirs(binaries_dir, exist_ok=True)
        tmp_file = os.path.join(CUCKOO_ROOT, filename)
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

        try:
            web_conf.general.existent_tasks = True
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


