from unittest.mock import patch

from analysis import views as analysis_views
from django.conf import settings
from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase
import pytest


@pytest.mark.usefixtures("db", "tmp_cuckoo_root")
class TestTraceeWebUI(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.orig_mongodb = analysis_views.enabledconf.get("mongodb", False)
        self.orig_tracee = analysis_views.enabledconf.get("tracee", False)

    def tearDown(self):
        analysis_views.enabledconf["mongodb"] = self.orig_mongodb
        analysis_views.enabledconf["tracee"] = self.orig_tracee

    def test_base_template_does_not_load_tracee_assets_globally(self):
        rendered = render_to_string("base.html", {"STATIC_URL": "/static/", "csrf_token": "tok"})
        self.assertNotIn("pako_inflate.min.js", rendered)
        self.assertNotIn("datatables.min.js", rendered)
        self.assertNotIn("datatables.min.css", rendered)

    def test_tracee_partial_lazy_loads_assets_and_handles_empty_state(self):
        empty_html = render_to_string("analysis/tracee/index.html", {"STATIC_URL": "/custom-static/", "tracee": {}})
        self.assertIn("No tracee.", empty_html)
        self.assertNotIn("pako_inflate.min.js", empty_html)
        self.assertNotIn('id="tracee"', empty_html)

        populated_html = render_to_string(
            "analysis/tracee/index.html",
            {"STATIC_URL": "/custom-static/", "tracee": {"rawData": "eJwFwQEBAAAAgJD+r+4ICg=="}},
        )
        self.assertIn('loadStyleOnce("/custom-static/css/datatables.min.css")', populated_html)
        self.assertIn('loadScriptOnce("/custom-static/js/pako_inflate.min.js", "pako")', populated_html)
        self.assertIn('loadScriptOnce("/custom-static/js/datatables.min.js", "DataTable")', populated_html)
        self.assertNotIn('src="/static/js/pako_inflate.min.js"', populated_html)
        self.assertNotIn('id="tracee"', populated_html)

    def test_report_template_gates_tracee_tab_on_linux_and_config_enabled(self):
        base_ctx = {
            "STATIC_URL": "/static/",
            "csrf_token": "tok",
            "settings": settings,
            "analysis": {
                "info": {
                    "id": 65,
                    "category": "url",
                    "machine": {"platform": "linux"},
                    "options": {},
                    "comments": [],
                },
                "target": {"category": "url", "url": "http://example.com"},
            },
        }

        hidden_html = render_to_string("analysis/report.html", {**base_ctx, "config": {"tracee": False}})
        self.assertNotIn('id="tracee-tab"', hidden_html)
        self.assertNotIn('id="tracee"', hidden_html)

        shown_html = render_to_string("analysis/report.html", {**base_ctx, "config": {"tracee": True}})
        self.assertIn('id="tracee-tab"', shown_html)
        self.assertIn('hx-get="/analysis/load_files/65/tracee/"', shown_html)
        self.assertEqual(shown_html.count('id="tracee"'), 1)

        win_ctx = {
            **base_ctx,
            "analysis": {
                **base_ctx["analysis"],
                "info": {**base_ctx["analysis"]["info"], "machine": {"platform": "windows"}},
            },
            "config": {"tracee": True},
        }
        win_html = render_to_string("analysis/report.html", win_ctx)
        self.assertNotIn('id="tracee-tab"', win_html)
        self.assertNotIn('id="tracee"', win_html)

    def test_load_files_tracee_handles_missing_and_present_mongo_data(self):
        analysis_views.enabledconf["mongodb"] = True
        req = self.factory.get("/analysis/load_files/65/tracee/", HTTP_X_REQUESTED_WITH="XMLHttpRequest")

        with patch.object(analysis_views, "mongo_find_one", return_value={"info": {"tlp": ""}}, create=True):
            resp_empty = analysis_views.load_files(req, 65, "tracee")
        self.assertEqual(resp_empty.status_code, 200)
        self.assertIn(b"No tracee.", resp_empty.content)

        with patch.object(analysis_views, "mongo_find_one", return_value=None, create=True):
            resp_none = analysis_views.load_files(req, 65, "tracee")
        self.assertEqual(resp_none.status_code, 200)
        self.assertIn(b"No tracee.", resp_none.content)

        with patch.object(
            analysis_views,
            "mongo_find_one",
            return_value={"tracee": "eJwFwQEBAAAAgJD+r+4ICg==", "info": {"tlp": ""}},
            create=True,
        ):
            resp_ok = analysis_views.load_files(req, 65, "tracee")
        self.assertEqual(resp_ok.status_code, 200)
        self.assertIn(b"pako_inflate.min.js", resp_ok.content)
        self.assertIn(b"eJwFwQEBAAAAgJD+r+4ICg==", resp_ok.content)
