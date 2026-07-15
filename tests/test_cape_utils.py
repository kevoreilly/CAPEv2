import unittest
from unittest.mock import MagicMock, patch

from lib.cuckoo.common.cape_utils import cape_name_from_yara, static_config_lookup, static_config_parsers


class TestCapeUtils(unittest.TestCase):
    @patch("lib.cuckoo.common.cape_utils.File.yara_hit_provides_detection")
    @patch("lib.cuckoo.common.cape_utils.File.get_cape_name_from_yara_hit")
    def test_cape_name_from_yara(self, mock_get_cape_name_from_yara_hit, mock_yara_hit_provides_detection):
        details = {"cape_yara": [{"rule": "test_rule_1"}, {"rule": "test_rule_2"}]}
        pid = 1234
        results = {}

        mock_yara_hit_provides_detection.side_effect = [False, True]
        mock_get_cape_name_from_yara_hit.return_value = "test_name"

        name = cape_name_from_yara(details, pid, results)

        self.assertEqual(name, "test_name")
        self.assertIn("detections2pid", results)
        self.assertIn(str(pid), results["detections2pid"])
        self.assertIn("test_name", results["detections2pid"][str(pid)])

    @patch("lib.cuckoo.common.cape_utils.File.yara_hit_provides_detection")
    def test_cape_name_from_yara_no_detection(self, mock_yara_hit_provides_detection):
        details = {"cape_yara": [{"rule": "test_rule_1"}]}
        pid = 1234
        results = {}

        mock_yara_hit_provides_detection.return_value = False

        name = cape_name_from_yara(details, pid, results)

        self.assertIsNone(name)
        self.assertNotIn("detections2pid", results)

    def test_cape_name_from_yara_no_cape_yara(self):
        details = {}
        pid = 1234
        results = {}

        name = cape_name_from_yara(details, pid, results)

        self.assertIsNone(name)
        self.assertNotIn("detections2pid", results)


class TestStaticConfigParsers(unittest.TestCase):
    @patch("lib.cuckoo.common.cape_utils.HAVE_CAPE_EXTRACTORS", True)
    @patch("lib.cuckoo.common.cape_utils.cape_malware_parsers")
    def test_static_config_parsers_cape_extractors(self, mock_cape_malware_parsers):
        cape_name = "test_cape"
        file_path = "/path/to/file"
        file_data = b"test data"
        mock_parser = MagicMock()
        mock_parser.extract_config.return_value = {"key": "value"}
        mock_cape_malware_parsers.__contains__.return_value = True
        mock_cape_malware_parsers.__getitem__.return_value = mock_parser
        result = static_config_parsers(cape_name, file_path, file_data)
        self.assertIn(cape_name, result)
        self.assertIn("key", result[cape_name])
        self.assertEqual(result[cape_name]["key"], ["value"])

    def test_static_config_parsers_no_extractors(self):
        cape_name = "test_none"
        file_path = "/path/to/file"
        file_data = b"test data"
        result = static_config_parsers(cape_name, file_path, file_data)
        self.assertEqual(result, {})


class TestStaticConfigLookupES(unittest.TestCase):
    """static_config_lookup ES branch: MT-off must be byte-for-byte upstream;
    MT-on must scope + return None on no hits."""

    def _run(self, es_hits, esf):
        # Force the ES branch: mongo disabled, es enabled.
        with patch("lib.cuckoo.common.cape_utils.repconf") as mock_repconf, patch(
            "lib.cuckoo.common.cape_utils.es", create=True
        ) as mock_es, patch(
            "lib.cuckoo.common.cape_utils.get_analysis_index", return_value="cuckoo-*", create=True
        ), patch(
            "lib.cuckoo.common.cape_utils._config_lookup_es_filter", return_value=esf
        ):
            mock_repconf.mongodb.enabled = False
            mock_repconf.elasticsearchdb.enabled = True
            mock_es.search.return_value = {"hits": {"hits": es_hits}}
            result = static_config_lookup("/path/to/file", sha256="a" * 64, viewer=object())
            return result, mock_es

    def test_es_mt_off_uses_upstream_match_query(self):
        # MT off => filter is None => original upstream query (match) + [0]["_source"].
        hit_source = {"CAPE": {"configs": [{"x": 1}]}, "info": {"id": 7}}
        result, mock_es = self._run(es_hits=[{"_source": hit_source}], esf=None)
        self.assertEqual(result, {"id": 7})
        body = mock_es.search.call_args.kwargs["body"]
        # Upstream shape: match query, no bool/filter.
        self.assertEqual(body["query"], {"match": {"target.file.sha256": "a" * 64}})
        self.assertNotIn("bool", body["query"])

    def test_es_mt_off_no_hits_raises_indexerror(self):
        # Preserve upstream no-hits behavior (IndexError) when MT off.
        with self.assertRaises(IndexError):
            self._run(es_hits=[], esf=None)

    def test_es_mt_on_uses_scoped_term_query_and_returns_none_on_empty(self):
        esf = {"bool": {"should": [{"term": {"info.visibility": "public"}}], "minimum_should_match": 1}}
        result, mock_es = self._run(es_hits=[], esf=esf)
        self.assertIsNone(result)
        body = mock_es.search.call_args.kwargs["body"]
        self.assertIn("bool", body["query"])
        self.assertEqual(body["query"]["bool"]["must"], [{"term": {"target.file.sha256": "a" * 64}}])
        self.assertEqual(body["query"]["bool"]["filter"], [esf])

    def test_es_mt_on_returns_scoped_hit(self):
        esf = {"bool": {"should": [{"term": {"info.visibility": "public"}}], "minimum_should_match": 1}}
        hit_source = {"CAPE": {"configs": [{"x": 1}]}, "info": {"id": 9}}
        result, _ = self._run(es_hits=[{"_source": hit_source}], esf=esf)
        self.assertEqual(result, {"id": 9})


if __name__ == "__main__":
    unittest.main()
