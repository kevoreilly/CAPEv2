from tempfile import NamedTemporaryFile
from unittest.mock import ANY, MagicMock, patch

import pytest

from lib.cuckoo.common.objects import File
from modules.processing.CAPE import CAPE
from modules.processing.deduplication import reindex_screenshots


@pytest.fixture
def cape_processor():
    retval = CAPE()
    retval._set_dict_keys()
    yield retval


class TestConfigUpdates:
    def test_update_no_config(self, cape_processor):
        cape_processor.update_cape_configs("Family", None, MagicMock())
        assert cape_processor.cape["configs"] == []

    def test_update_empty_config(self, cape_processor):
        cape_processor.update_cape_configs("Family", {}, MagicMock())
        assert cape_processor.cape["configs"] == []

    def test_update_single_config(self, cape_processor):
        cfg = {"Family": {"SomeKey": "SomeValue"}}
        cape_processor.update_cape_configs("Family", cfg, MagicMock())
        expected_cfgs = [cfg]
        assert cape_processor.cape["configs"] == expected_cfgs

    def test_update_multiple_configs(self, cape_processor):
        cfg1 = {"Family": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family": {"AnotherKey": "AnotherValue"}}
        cape_processor.update_cape_configs("Family", cfg1, MagicMock())
        cape_processor.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfgs = [{"Family": {"AnotherKey": "AnotherValue", "SomeKey": "SomeValue"}, "_associated_config_hashes": ANY}]
        assert cape_processor.cape["configs"] == expected_cfgs

    def test_update_different_families(self, cape_processor):
        cfg1 = {"Family1": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family2": {"SomeKey": "SomeValue"}}
        cape_processor.update_cape_configs("Family", cfg1, MagicMock())
        cape_processor.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfgs = [
            {"Family1": {"SomeKey": "SomeValue"}, "_associated_config_hashes": ANY},
            {"Family2": {"SomeKey": "SomeValue"}, "_associated_config_hashes": ANY},
        ]
        assert cape_processor.cape["configs"] == expected_cfgs

    def test_update_same_family_overwrites(self, cape_processor):
        # see https://github.com/kevoreilly/CAPEv2/pull/1357
        cfg1 = {"Family": {"SomeKey": "SomeValue"}}
        cfg2 = {"Family": {"SomeKey": "DifferentValue"}}
        cape_processor.update_cape_configs("Family", cfg1, MagicMock())
        cape_processor.update_cape_configs("Family", cfg2, MagicMock())
        expected_cfg = [
            {"Family": {"SomeKey": "DifferentValue"}, "_associated_config_hashes": ANY},
        ]
        assert cape_processor.cape["configs"] == expected_cfg

    def test_update_config_file_obj(self, cape_processor):
        with NamedTemporaryFile(mode="wb") as f:
            f.write(b"fake file for configs")
            file_obj = File(f.name).get_all_hashes()
            cfg = {"Family": {"SomeKey": "SomeValue"}}
            cape_processor.update_cape_configs("Family", cfg, file_obj)
        actual_cfg = cape_processor.cape["configs"]
        assert "Family" in actual_cfg[0]
        assert "_associated_config_hashes" in actual_cfg[0]
        hashes = actual_cfg[0]["_associated_config_hashes"]
        assert len(hashes) == 1
        assert hashes[0]["md5"].startswith("d41")
        assert hashes[0]["sha1"].startswith("da3")
        assert hashes[0]["sha256"].startswith("e3b")
        assert hashes[0]["sha512"].startswith("cf8")
        assert hashes[0]["sha3_384"].startswith("0c6")


class TestAnalysisConfigLinks:
    @pytest.mark.parametrize("category", ["static", "file"])
    def test_analysis_linkability(self, category, cape_processor):
        cape_processor.results = {"target": {"category": category}}
        hashes = {
            "md5": "fake-md5",
            "sha1": "fake-sha1",
            "sha256": "fake-sha256",
            "sha512": "fake-sha512",
            "sha3_384": "fake-sha3_384",
        }
        cape_processor.results["target"]["file"] = hashes
        cfg = {"Family": {"SomeKey": "DifferentValue"}}
        cape_processor.cape["configs"] = [cfg]
        cape_processor.link_configs_to_analysis()
        assert "_associated_analysis_hashes" in cfg
        assert cfg["_associated_analysis_hashes"] == hashes

    @pytest.mark.parametrize("category", ["resubmit", "sample", "pcap", "url", "dlnexec", "vtdl"])
    def test_static_links(self, category, cape_processor):
        cape_processor.results = {"target": {"category": category}}
        cfg = {"Family": {"SomeKey": "DifferentValue"}}
        cape_processor.cape["configs"] = [cfg]
        cape_processor.link_configs_to_analysis()
        assert "_associated_analysis_hashes" not in cfg


class TestDeduplication:
    @patch("os.rename")
    @patch("os.listdir")
    def test_reindex(self, os_listdir, os_rename):
        dirlist = ["foo.jpg", "bar.jpg", "baz.jpg"]
        os_listdir.return_value = dirlist
        reindex_screenshots("shots")
        assert os_rename.call_count == 3
        os_rename.assert_any_call("shots/bar.jpg", "shots/0000.jpg")
        os_rename.assert_any_call("shots/baz.jpg", "shots/0001.jpg")
        os_rename.assert_any_call("shots/foo.jpg", "shots/0002.jpg")


class TestThreatIntelligence:
    def test_promote_detections_by_default_and_annotate_dns_answers(self):
        from lib.cuckoo.common.integrations.threatintelligence.base import (
            FamilyCard,
            IND_DOMAIN,
            IND_IP,
            IntelMatch,
            ProviderResult,
        )
        from modules.processing.threatintelligence import ThreatIntelligence

        class FakeIndicatorProvider:
            name = "threatfox"
            supported_indicators = {IND_IP, IND_DOMAIN}

            def accepts_indicator(self, it):
                return it in self.supported_indicators

            def lookup(self, indicator, indicator_type, ports=None):
                res = ProviderResult(status="ok")
                if indicator == "c2.example.org":
                    res.matches = [
                        IntelMatch(
                            source="threatfox",
                            indicator=indicator,
                            indicator_type=indicator_type,
                            ioc="c2.example.org",
                            ioc_id="12345",
                            indicator_url="https://threatfox.abuse.ch/ioc/12345/",
                            threat_type="payload_delivery",
                            malware="win.lumma",
                            malware_printable="Lumma Stealer",
                            confidence_level=75,
                        )
                    ]
                elif indicator == "198.51.100.42":
                    res.matches = [
                        IntelMatch(
                            source="threatfox",
                            indicator=indicator,
                            indicator_type=indicator_type,
                            ioc="198.51.100.42:443",
                            ioc_id="67890",
                            indicator_url="https://threatfox.abuse.ch/ioc/67890/",
                            threat_type="botnet_cc",
                            malware="win.cobalt_strike",
                            malware_printable="Cobalt Strike",
                            confidence_level=100,
                        ),
                        IntelMatch(
                            source="threatfox",
                            indicator=indicator,
                            indicator_type=indicator_type,
                            ioc="198.51.100.42:8080",
                            threat_type="botnet_cc",
                            malware="win.unknown",
                            malware_printable="Unknown malware",
                            confidence_level=100,
                        ),
                    ]
                else:
                    res.status = "no_match"
                return res

        class FakeFamilyProvider:
            name = "malpedia"

            def enrich(self, query, is_id=False, provenance=None):
                return FamilyCard(
                    source="malpedia",
                    family_id=query if is_id else f"win.{query}",
                    common_name="Cobalt Strike" if "cobalt" in query else "Lumma Stealer",
                    description="Test family description",
                    provenance=provenance,
                )

        ti = ThreatIntelligence()
        ti.results = {
            "network": {
                "hosts": [{"ip": "198.51.100.42", "ports": [443]}],
                "domains": [{"domain": "dga.example.net", "ip": "198.51.100.42"}],
                "dns": [
                    {
                        "request": "c2.example.org",
                        "answers": [{"type": "A", "data": "203.0.113.5"}],
                    },
                    {
                        "request": "dga.example.net",
                        "answers": [{"type": "A", "data": "198.51.100.42"}],
                    },
                ],
                "http_ex": [
                    {"protocol": "https", "host": "c2.example.org", "uri": "/gate.php", "dst": "203.0.113.5"}
                ],
            }
        }

        fake_cfg = MagicMock()
        fake_cfg.globals = {"cache": False, "concurrent_lookups": False}
        fake_cfg.section.return_value = {"from_threatfox": True}

        with (
            patch("modules.processing.threatintelligence.load_config", return_value=fake_cfg),
            patch(
                "modules.processing.threatintelligence.get_enabled_indicator_providers",
                return_value=[FakeIndicatorProvider()],
            ),
            patch(
                "modules.processing.threatintelligence.get_enabled_family_providers",
                return_value=[FakeFamilyProvider()],
            ),
            patch("modules.processing.threatintelligence.get_enabled_actor_providers", return_value=[]),
        ):
            out = ti.run()

        # Both Lumma Stealer (payload_delivery, confidence 75) and Cobalt Strike (botnet_cc, 100)
        # should promote to results["detections"], while "Unknown malware" is filtered out.
        det_families = [d["family"] for d in ti.results.get("detections", [])]
        assert "Lumma Stealer" in det_families
        assert "Cobalt Strike" in det_families
        assert "Unknown malware" not in det_families

        # Provenance on family cards must reflect ThreatFox, not self-polluted cape_detection.
        for fam_card in out["families"]:
            assert "cape_detection" not in fam_card["provenance"]

        # DNS request and DNS answer IP and post-analysis lookup IP and http_ex should be annotated.
        dns_rows = ti.results["network"]["dns"]
        assert dns_rows[0].get("threatintel")
        assert dns_rows[1]["answers"][0].get("threatintel")
        assert dns_rows[1].get("lookup_threatintel")
        assert ti.results["network"]["http_ex"][0].get("threatintel")

    def test_service_icons_and_template_contracts(self):
        from pathlib import Path
        from analysis.templatetags.analysis_tags import (
            ext_lookup,
            ext_service_icon,
            threatintel_badges,
        )
        from django.template.loader import render_to_string

        vt_html = str(ext_lookup("vt", "example.com", "domain"))
        assert "https://www.virustotal.com/gui/domain/example.com/detection" in vt_html
        assert "<svg" in vt_html
        assert "ext-svc-vt" in vt_html

        badges_html = str(
            threatintel_badges(
                [
                    {
                        "source": "threatfox",
                        "tag": "botnet_cc:cobalt strike",
                        "tooltip": "threatfox | confidence 100%",
                        "indicator_url": "https://threatfox.abuse.ch/ioc/1/",
                    }
                ]
            )
        )
        assert "ti-pill" in badges_html
        assert "botnet_cc:cobalt strike" in badges_html
        assert "https://threatfox.abuse.ch/ioc/1/" in badges_html
        assert "<svg" in badges_html
        assert "<svg" in str(ext_service_icon("malpedia"))

        dns_entry = {
            "request": "evil.example.com",
            "answers": [
                {
                    "type": "A",
                    "data": "198.51.100.42",
                    "threatintel": [
                        {
                            "source": "threatfox",
                            "tag": "botnet_cc:cobalt strike",
                            "tooltip": "threatfox | confidence 100%",
                            "indicator_url": "https://threatfox.abuse.ch/ioc/2/",
                        }
                    ],
                }
            ],
            "threatintel": [
                {
                    "source": "threatfox",
                    "tag": "payload_delivery:lumma stealer",
                    "tooltip": "threatfox | confidence 75%",
                    "indicator_url": "https://threatfox.abuse.ch/ioc/1/",
                }
            ],
        }
        rendered_dns = render_to_string(
            "analysis/network/_dns.html",
            {"network": {"dns": [dns_entry]}, "config": {"display_et_portal": True, "display_pt_portal": True}},
        )
        assert "payload_delivery:lumma stealer" in rendered_dns
        assert "botnet_cc:cobalt strike" in rendered_dns
        assert "ext-svc-vt" in rendered_dns
        assert "ext-svc-et" in rendered_dns
        assert "ext-svc-pt" in rendered_dns

        rendered_dns_not_ajax = render_to_string(
            "analysis/network/_dns_not_ajax.html",
            {"analysis": {"network": {"dns": [dns_entry]}}, "config": {}},
        )
        assert "payload_delivery:lumma stealer" in rendered_dns_not_ajax
        assert "botnet_cc:cobalt strike" in rendered_dns_not_ajax

        repo_root = Path(__file__).resolve().parent.parent
        info_tpl = (repo_root / "web/templates/analysis/overview/_info.html").read_text()
        ti_tpl = (repo_root / "web/templates/analysis/overview/_threat_intel.html").read_text()
        sig_tpl = (repo_root / "web/templates/analysis/overview/_signatures.html").read_text()
        hosts_tpl = (repo_root / "web/templates/analysis/network/_hosts.html").read_text()

        # Threat intel is included in _info.html under Detection(s)/Status and collapsed by default.
        assert 'include "analysis/overview/_threat_intel.html"' in info_tpl
        assert 'aria-expanded="false"' in ti_tpl
        # Signatures template no longer uses w-50 or middle chevron arrow.
        assert "w-50" not in sig_tpl
        assert "fa-chevron-down" not in sig_tpl
        # _hosts.html checks 192.168 before opening <tr>.
        assert hosts_tpl.index('host.ip|slice:":7" != "192.168"') < hosts_tpl.index("<tr>\n                            {% if")
