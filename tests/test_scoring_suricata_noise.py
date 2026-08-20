"""Tests for the suricata_alert decoder-noise guard in calc_scoring."""

from lib.cuckoo.common.scoring import _suricata_alerts_are_noise_only, calc_scoring

SURI_SIG = {"name": "suricata_alert", "categories": ["network"], "severity": 3, "confidence": 80, "weight": 4}
WEAK_SIG = {"name": "stealth_network", "categories": ["stealth"], "severity": 1, "confidence": 100, "weight": 1}

DECODER_ALERT = {"sid": 2221033, "severity": 3, "signature": "SURICATA HTTP Request abnormal Content-Encoding header"}
ET_MALWARE_ALERT = {"sid": 2027758, "severity": 1, "signature": "ET MALWARE Cobalt Strike Beacon Observed"}
ET_INFO_ALERT = {"sid": 2013028, "severity": 3, "signature": "ET POLICY curl User-Agent Outbound"}


def _url_results(alerts):
    return {"target": {"category": "url"}, "suricata": {"alerts": alerts}}


class TestSuricataAlertsAreNoiseOnly:
    def test_no_alerts_is_noise(self):
        assert _suricata_alerts_are_noise_only({"suricata": {"alerts": []}})
        assert _suricata_alerts_are_noise_only({})

    def test_decoder_events_are_noise(self):
        assert _suricata_alerts_are_noise_only({"suricata": {"alerts": [DECODER_ALERT] * 15}})

    def test_low_priority_et_is_noise(self):
        assert _suricata_alerts_are_noise_only({"suricata": {"alerts": [ET_INFO_ALERT]}})

    def test_real_et_alert_is_not_noise(self):
        assert not _suricata_alerts_are_noise_only({"suricata": {"alerts": [DECODER_ALERT, ET_MALWARE_ALERT]}})

    def test_missing_severity_defaults_to_noise(self):
        assert _suricata_alerts_are_noise_only({"suricata": {"alerts": [{"signature": "whatever"}]}})


class TestCalcScoringSuricataNoiseGuard:
    def test_url_decoder_noise_excludes_suricata_alert(self):
        # Without the guard, suricata_alert alone contributes 4 * 2 * 0.8 = 6.4
        # and benign browsing (SID 2221033 fires on Chrome/Edge zstd) lands at
        # Suspicious. With the guard, only the weak signature (0.5) remains.
        score, status = calc_scoring(_url_results([DECODER_ALERT] * 15), [dict(SURI_SIG), dict(WEAK_SIG)])
        assert score == 0.5
        assert status == "Clean"

    def test_url_real_et_alert_keeps_suricata_alert(self):
        score, status = calc_scoring(_url_results([DECODER_ALERT, ET_MALWARE_ALERT]), [dict(SURI_SIG), dict(WEAK_SIG)])
        assert score == 6.9
        assert status == "Suspicious"

    def test_report_signature_list_is_not_mutated(self):
        matched = [dict(SURI_SIG), dict(WEAK_SIG)]
        calc_scoring(_url_results([DECODER_ALERT]), matched)
        assert [m["name"] for m in matched] == ["suricata_alert", "stealth_network"]
