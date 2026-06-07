from unittest.mock import MagicMock, patch
import json
import pytest
from django.conf import settings
from django.test import SimpleTestCase
from analysis.views import enabledconf


@pytest.mark.usefixtures("db")
class TestHuntViews(SimpleTestCase):
    def setUp(self):
        self.original_mongodb_enabled = enabledconf["mongodb"]
        self.original_hunt_enabled = getattr(settings, "HUNT_ENABLED", False)
        self.original_web_auth = getattr(settings, "WEB_AUTHENTICATION", False)
        settings.HUNT_ENABLED = True
        settings.WEB_AUTHENTICATION = False

    def tearDown(self):
        enabledconf["mongodb"] = self.original_mongodb_enabled
        settings.HUNT_ENABLED = self.original_hunt_enabled
        settings.WEB_AUTHENTICATION = self.original_web_auth

    def test_hunt_page_requires_enabled_setting(self):
        """If HUNT_ENABLED is set to False in settings (via web.conf), the page should render an error."""
        settings.HUNT_ENABLED = False
        response = self.client.get("/analysis/hunt/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("The Hunt/Threat Discovery feature is disabled in web.conf", response.content.decode())

    def test_hunt_page_requires_mongodb(self):
        """If MongoDB is disabled, the hunt page should render an error."""
        enabledconf["mongodb"] = False
        response = self.client.get("/analysis/hunt/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("MongoDB is required", response.content.decode())

    def test_hunt_page_prevents_global_all_time_hunt(self):
        """If filename_prefix is blank and days_back is set to 0 (All Time), render a database performance safeguard error."""
        enabledconf["mongodb"] = True
        response = self.client.get("/analysis/hunt/?filename_prefix=&days_back=0")
        self.assertEqual(response.status_code, 200)
        self.assertIn("An all-time global hunt with no filename prefix is not allowed", response.content.decode())

    @patch("lib.cuckoo.common.hunting.os.path.exists")
    def test_hunt_page_error_when_config_missing(self, mock_exists):
        """If hunt.json is missing from disk, render a clean error page and block execution."""
        mock_exists.return_value = False
        enabledconf["mongodb"] = True
        response = self.client.get("/analysis/hunt/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("The hunt.json configuration file is missing", response.content.decode())

    @patch("lib.cuckoo.common.hunting.os.path.getmtime")
    @patch("lib.cuckoo.common.hunting.os.path.exists")
    @patch("lib.cuckoo.common.hunting.open")
    def test_hunt_page_error_when_config_invalid(self, mock_open, mock_exists, mock_getmtime):
        """If hunt.json contains invalid syntax, log detailed tracebacks internally and render a secure error page."""
        mock_exists.return_value = True
        mock_getmtime.return_value = 12345678.0
        mock_open.side_effect = ValueError("Invalid JSON syntax")
        enabledconf["mongodb"] = True
        response = self.client.get("/analysis/hunt/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("The hunt.json configuration file is invalid", response.content.decode())

    @patch("analysis.views.mongo_aggregate", create=True)
    def test_hunt_page_success_renders_template(self, mock_mongo_aggregate):
        """The hunt page should render facets correctly after whitelisting system noise."""
        enabledconf["mongodb"] = True

        # Mock MongoDB returning aggregations with noise and signal
        mock_mongo_aggregate.return_value = [{
            "domains": [
                {"_id": "malicious-c2.com", "count": 5, "task_ids": {101, 102}},
                {"_id": "crl.microsoft.com", "count": 20, "task_ids": {101, 102}} # Should be whitelisted out
            ],
            "ips": [
                {"_id": "185.190.140.1", "count": 4, "task_ids": {101, 102}},
                {"_id": "127.0.0.1", "count": 10, "task_ids": {101}} # Private IP, should be whitelisted out
            ],
            "mutexes": [
                {"_id": "EvilCampaignMutex", "count": 3, "task_ids": {101, 102}},
                {"_id": "Local\\ZoneBaseMutex", "count": 15, "task_ids": {101}} # Whitelisted out
            ],
            "dropped_files": [
                {"_id": "C:\\Windows\\Temp\\payload.exe", "count": 3, "task_ids": {101, 102}},
                {"_id": "Device\\KsecDD", "count": 10, "task_ids": {101}} # Whitelisted out
            ],
            "executed_commands": [
                {"_id": "powershell.exe -enc BADCODE", "count": 4, "task_ids": {101, 102}},
                {"_id": "chcp", "count": 12, "task_ids": {101}} # Whitelisted out
            ],
            "registry_keys": [
                {"_id": "HKCU\\Software\\EvilKey", "count": 3, "task_ids": {101, 102}},
                {"_id": "HKLM\\SOFTWARE\\Microsoft\\CTF\\", "count": 14, "task_ids": {101}} # Whitelisted out
            ],
            "dropped_hashes": [
                {"_id": "a" * 64, "count": 4, "task_ids": {101, 102}},
                {"_id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "count": 12, "task_ids": {101}} # Blank hash, should be filtered
            ],
            "procdump_hashes": [
                {"_id": "b" * 64, "count": 3, "task_ids": {101, 102}},
                {"_id": "invalid_hash_len", "count": 10, "task_ids": {101}} # Invalid hash length, filtered
            ],
            "extracted_hashes": [
                {"_id": "c" * 64, "count": 5, "task_ids": {101, 102}}
            ],
            "imphashes": [
                {"_id": "d" * 32, "count": 4, "task_ids": {101, 102}},
                {"_id": "invalid_imphash_len", "count": 15, "task_ids": {101}} # Invalid imphash length, filtered
            ],
            "http_uris": [
                {"_id": "/api/v1/beacon.php", "count": 6, "task_ids": {101, 102}}
            ],
            "signatures": [
                {"_id": "has_pogo_autorun", "count": 8, "task_ids": {101, 102}}
            ]
        }]

        response = self.client.get("/analysis/hunt/?filename_prefix=downloaded_by_&min_count=2&days_back=14")
        self.assertEqual(response.status_code, 200)

        html_content = response.content.decode()

        # Check that title / elements are present
        self.assertIn("Threat Discovery & Hunting", html_content)

        # Check signal values are rendered
        self.assertIn("malicious-c2.com", html_content)
        self.assertIn("185.190.140.1", html_content)
        self.assertIn("EvilCampaignMutex", html_content)
        self.assertIn("payload.exe", html_content)
        self.assertIn("powershell.exe -enc BADCODE", html_content)
        self.assertIn("HKCU\\Software\\EvilKey", html_content)
        self.assertIn("a" * 64, html_content)
        self.assertIn("b" * 64, html_content)
        self.assertIn("c" * 64, html_content)
        self.assertIn("d" * 32, html_content)
        self.assertIn("/api/v1/beacon.php", html_content)
        self.assertIn("has_pogo_autorun", html_content)

        # Ensure whitelisted / noise items are successfully filtered out and not rendered
        self.assertNotIn("crl.microsoft.com", html_content)
        self.assertNotIn("127.0.0.1", html_content)
        self.assertNotIn("ZoneBaseMutex", html_content)
        self.assertNotIn("Device\\KsecDD", html_content)
        self.assertNotIn("HKLM\\SOFTWARE\\Microsoft\\CTF\\", html_content)
        self.assertNotIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", html_content)
        self.assertNotIn("invalid_hash_len", html_content)
        self.assertNotIn("invalid_imphash_len", html_content)

        # Verify query parameters are passed back to forms
        self.assertIn('value="downloaded_by_"', html_content)
        self.assertIn('value="2"', html_content)
        # Select box selection option checked
        self.assertIn('<option value="14" selected>Last 14 Days</option>', html_content)

    @patch("analysis.views.mongo_aggregate", create=True)
    def test_hunt_page_blank_prefix_works(self, mock_mongo_aggregate):
        """When filename_prefix is left blank, the match query should skip the target.file.name check to allow global hunting."""
        enabledconf["mongodb"] = True
        mock_mongo_aggregate.return_value = [{}]

        response = self.client.get("/analysis/hunt/?filename_prefix=&min_count=2&days_back=7")
        self.assertEqual(response.status_code, 200)

        # Ensure mongo_aggregate was called
        self.assertTrue(mock_mongo_aggregate.called)
        called_pipeline = mock_mongo_aggregate.call_args[0][1]

        # Extract the $match stage from the pipeline
        match_stage = called_pipeline[0]["$match"]

        # Assert that 'target.file.name' was omitted from the match query
        self.assertNotIn("target.file.name", match_stage)
        self.assertIn("malfamily", match_stage)
        self.assertIn("detections", match_stage)
        self.assertIn("info.started", match_stage)
        self.assertEqual(match_stage["detections"], {"$exists": False})

    @patch("analysis.views.mongo_aggregate", create=True)
    def test_hunt_page_ignore_detections_toggle_works(self, mock_mongo_aggregate):
        """When ignore_detections is toggled ON, the query should completely skip malfamily and detections filters."""
        enabledconf["mongodb"] = True
        mock_mongo_aggregate.return_value = [{}]

        # Send ignore_detections=on (standard GET form checkbox format)
        response = self.client.get("/analysis/hunt/?filename_prefix=downloaded_by_&min_count=2&days_back=7&ignore_detections=on")
        self.assertEqual(response.status_code, 200)

        # Ensure mongo_aggregate was called
        self.assertTrue(mock_mongo_aggregate.called)
        called_pipeline = mock_mongo_aggregate.call_args[0][1]

        # Extract the $match stage from the pipeline
        match_stage = called_pipeline[0]["$match"]

        # Assert that 'malfamily' and 'detections' were skipped
        self.assertNotIn("malfamily", match_stage)
        self.assertNotIn("detections", match_stage)
        self.assertIn("target.file.name", match_stage)

    @patch("analysis.views.db.session.get")
    @patch("analysis.views.db.session.commit")
    def test_tag_tasks_endpoint_works(self, mock_commit, mock_get):
        """The tag_tasks API should properly add and append custom tags to SQL Task entries."""
        # Use side_effect to return distinct Task mocks for each call, avoiding mock mutation reuse
        def mock_get_task(model, tid):
            task = MagicMock()
            task.tags_tasks = "existing_tag"
            return task
        mock_get.side_effect = mock_get_task

        payload = {"task_ids": [101, 102], "tag": "New_Campaign"}
        response = self.client.post(
            "/analysis/hunt/tag/",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)

        # Verify returned JSON response
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["tag"], "New_Campaign")
        self.assertEqual(data["updated_count"], 2)

        # Verify commit happened
        self.assertTrue(mock_commit.called)

    @patch("analysis.views.mongo_aggregate", create=True)
    def test_hunt_page_category_filtering_works(self, mock_mongo_aggregate):
        """The hunt page should dynamically construct pipeline facets based on untoggled category checkboxes."""
        enabledconf["mongodb"] = True
        mock_mongo_aggregate.return_value = [{}]

        # Submit form with only cat_domains and cat_ips enabled (others default to false when form submitted)
        response = self.client.get(
            "/analysis/hunt/?filename_prefix=downloaded_by_&min_count=2&days_back=7&cat_domains=on&cat_ips=on"
        )
        self.assertEqual(response.status_code, 200)

        # Verify mongo_aggregate was called with only those 2 facets
        self.assertTrue(mock_mongo_aggregate.called)
        called_pipeline = mock_mongo_aggregate.call_args[0][1]

        # Extract $facet stage
        facet_stage = called_pipeline[1]["$facet"]
        self.assertIn("domains", facet_stage)
        self.assertIn("ips", facet_stage)

        # Assert other facets were excluded to save database performance
        self.assertNotIn("mutexes", facet_stage)
        self.assertNotIn("dropped_files", facet_stage)
        self.assertNotIn("executed_commands", facet_stage)
        self.assertNotIn("registry_keys", facet_stage)
        self.assertNotIn("dropped_hashes", facet_stage)
        self.assertNotIn("procdump_hashes", facet_stage)
        self.assertNotIn("extracted_hashes", facet_stage)
        self.assertNotIn("imphashes", facet_stage)
        self.assertNotIn("http_uris", facet_stage)
        self.assertNotIn("signatures", facet_stage)

        # Verify template did not render untoggled panels
        html_content = response.content.decode()
        self.assertIn("Top Shared Domains", html_content)
        self.assertIn("Top Shared IPs", html_content)
        self.assertNotIn("Top Shared Mutexes", html_content)
        self.assertNotIn("Shared Registry Keys", html_content)
        self.assertNotIn("Unpacked Memory Hashes", html_content)
        self.assertNotIn("PE Import Hashes", html_content)
        self.assertNotIn("Shared HTTP Request URIs", html_content)
        self.assertNotIn("Shared Signatures", html_content)
