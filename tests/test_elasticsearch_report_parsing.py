"""Tests for the defensive report parsing in the Elasticsearch reporting module.

These cover the malformed shapes that used to raise TypeError/KeyError/
AttributeError and abort the whole reporting stage. The module imports cleanly
with [elasticsearchdb] disabled, so no Elasticsearch server is needed.
"""

from datetime import datetime

from modules.reporting.elasticsearchdb import ElasticSearchDB


def _report():
    # __init__ of Report expects runtime plumbing we do not need here: these
    # helpers only rewrite the dict they are handed.
    return ElasticSearchDB.__new__(ElasticSearchDB)


class TestFixSuricataHttpStatus:
    def test_missing_suricata_key(self):
        report = {}
        _report().fix_suricata_http_status(report)
        assert report == {}

    def test_suricata_is_not_a_dict(self):
        report = {"suricata": None}
        _report().fix_suricata_http_status(report)
        assert report["suricata"] is None

    def test_http_is_none_or_not_a_list(self):
        for value in (None, {}, "nope"):
            report = {"suricata": {"http": value}}
            _report().fix_suricata_http_status(report)
            assert report["suricata"]["http"] == value

    def test_non_dict_entries_are_skipped(self):
        report = {"suricata": {"http": [None, "x", 42, {"status": "None"}, {}]}}
        _report().fix_suricata_http_status(report)
        assert report["suricata"]["http"][3]["status"] is None

    def test_entry_without_status_key(self):
        report = {"suricata": {"http": [{"url": "/a"}]}}
        _report().fix_suricata_http_status(report)
        assert report["suricata"]["http"][0] == {"url": "/a"}

    def test_real_status_string_is_converted(self):
        report = {"suricata": {"http": [{"status": "None"}, {"status": "200"}]}}
        _report().fix_suricata_http_status(report)
        assert report["suricata"]["http"][0]["status"] is None
        assert report["suricata"]["http"][1]["status"] == "200"


class TestFixCapePayloads:
    def test_cape_is_not_a_dict(self):
        for value in (None, "CAPE", [], 3):
            report = {"CAPE": value}
            _report().fix_cape_payloads(report)
            assert report["CAPE"] == value

    def test_missing_cape_key(self):
        report = {}
        _report().fix_cape_payloads(report)
        assert report == {}

    def test_non_dict_payload_entries_are_skipped(self):
        report = {"CAPE": {"payloads": [None, "x", {"tlsh": False}]}}
        _report().fix_cape_payloads(report)
        assert report["CAPE"]["payloads"][2]["tlsh"] is None

    def test_payload_without_tlsh_key(self):
        report = {"CAPE": {"payloads": [{"sha256": "abc"}]}}
        _report().fix_cape_payloads(report)
        assert report["CAPE"]["payloads"][0] == {"sha256": "abc"}

    def test_tlsh_none_is_left_alone(self):
        # Only the literal False sentinel is normalised, not a real hash.
        report = {"CAPE": {"payloads": [{"tlsh": "T1A2B3"}]}}
        _report().fix_cape_payloads(report)
        assert report["CAPE"]["payloads"][0]["tlsh"] == "T1A2B3"


class TestFormatDatesDropped:
    def _base(self):
        return {
            "info": {"started": "2026-07-17 12:20:00", "ended": "2026-07-17 12:25:00"},
        }

    def test_missing_dropped_key(self):
        report = self._base()
        _report().format_dates(report)
        assert isinstance(report["info"]["started"], datetime)

    def test_non_dict_dropped_entries_are_skipped(self):
        report = self._base()
        report["dropped"] = [None, "x", 42]
        _report().format_dates(report)
        assert report["dropped"] == [None, "x", 42]

    def test_pe_is_not_a_dict(self):
        report = self._base()
        report["dropped"] = [{"pe": None}, {"pe": "nope"}]
        _report().format_dates(report)
        assert report["dropped"][0]["pe"] is None

    def test_pe_without_timestamp(self):
        report = self._base()
        report["dropped"] = [{"pe": {}}]
        _report().format_dates(report)
        assert report["dropped"][0]["pe"] == {}

    def test_pe_timestamp_already_a_datetime(self):
        already = datetime(2026, 7, 17, 12, 20, 0)
        report = self._base()
        report["dropped"] = [{"pe": {"timestamp": already}}]
        _report().format_dates(report)
        assert report["dropped"][0]["pe"]["timestamp"] is already

    def test_pe_timestamp_string_is_parsed(self):
        report = self._base()
        report["dropped"] = [{"pe": {"timestamp": "2026-07-17 12:20:00"}}]
        _report().format_dates(report)
        assert report["dropped"][0]["pe"]["timestamp"] == datetime(2026, 7, 17, 12, 20, 0)

    def test_machine_absent_or_none(self):
        for value in (None, "nope"):
            report = self._base()
            report["info"]["machine"] = value
            _report().format_dates(report)
            assert report["info"]["machine"] == value
