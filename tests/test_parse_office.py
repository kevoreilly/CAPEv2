import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import lib.cuckoo.common.integrations.parse_office as parse_office
from lib.cuckoo.common.integrations.parse_office import Office

data_dir = Path(__file__).parent / "data" / "office"
rtf_path = data_dir / "rtf_exploit.doc"


class TestParseOffice(unittest.TestCase):
    @patch("lib.cuckoo.common.integrations.parse_office.RtfObjParser")
    @patch("lib.cuckoo.common.integrations.parse_office.path_exists")
    @patch("lib.cuckoo.common.integrations.parse_office.hashlib.sha256")
    def test_parse_rtf(self, mock_sha256, mock_path_exists, MockRtfObjParser):
        # Setup
        mock_sha256.return_value.hexdigest.return_value = "dummy_sha256"
        mock_path_exists.return_value = False
        mock_rtfobj = MagicMock()
        mock_rtfobj.format_id = 1
        mock_rtfobj.is_package = False
        mock_rtfobj.is_ole = False
        mock_rtfobj.rawdata = b"rawdata"
        mock_rtfobj.start = 0
        MockRtfObjParser.return_value.objects = [mock_rtfobj]

        office = Office(
            file_path="dummy_path",
            task_id="dummy_task_id",
            sha256="dummy_sha256",
            options={},
        )

        # Execute
        result = office._parse_rtf(b"dummy_data")

        # Verify
        expected_result = {
            "1": [
                {
                    "class_name": "",
                    "size": len(mock_rtfobj.rawdata),
                    "filename": "object_00000000.raw",
                    "type_embed": "",
                    "CVE": "",
                    "sha256": "dummy_sha256",
                    "index": "00000000h",
                }
            ]
        }
        self.assertEqual(result, expected_result)


    @pytest.mark.skipif(not data_dir.exists(), reason="Required data file is not present")
    @pytest.mark.skipif(not rtf_path.exists(), reason="Required data file is not present")
    def test_parse_real_rtf(self):
        office = Office(
            file_path=rtf_path,
            task_id="1",
            sha256="5b307600b1ceb84f29315c95e5b21776eb6154b79214528629e4fc2310cd50e3",
            options={},
        )
        result = office._parse_rtf(Path(rtf_path).read_bytes())

        assert result == {
            "2": [
                {
                    "class_name": "Equation.3",
                    "size": 3584,
                    "filename": "object_0000272F.bin",
                    "type_embed": "Embedded",
                    "CVE": "Microsoft Equation 3.0 (Known Related to CVE-2017-11882 or CVE-2018-0802)",
                    "sha256": "c00b73082638eda4af3d5318aba64ae32d23f703a02c7338d5e34230a7855e70",
                    "index": "0000272Fh",
                }
            ]
        }

    def test_parse_rtf_records_extracted_files_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_bytes = b"MZ\x90\x00package-payload"
            ole_bytes = b"ole-object-payload"

            pkg_obj = SimpleNamespace(
                format_id=1,
                is_package=True,
                is_ole=False,
                filename="dropper.exe",
                src_path="C:\\temp\\dropper.exe",
                temp_path="",
                olepkgdata=pkg_bytes,
                start=0x10,
            )
            dup_pkg_obj = SimpleNamespace(
                format_id=1,
                is_package=True,
                is_ole=False,
                filename="duplicate.exe",
                src_path="",
                temp_path="",
                olepkgdata=pkg_bytes,
                start=0x20,
            )
            ole_obj = SimpleNamespace(
                format_id=2,
                is_package=False,
                is_ole=True,
                oledata_size=len(ole_bytes),
                clsid=None,
                clsid_desc="",
                class_name=b"Package",
                oledata=ole_bytes,
                start=0x30,
            )
            empty_raw_obj = SimpleNamespace(
                format_id=3,
                is_package=False,
                is_ole=False,
                rawdata=b"",
                start=0x40,
            )

            with (
                patch.object(parse_office, "CUCKOO_ROOT", tmpdir),
                patch.object(parse_office, "RtfObjParser") as mock_parser_cls,
            ):
                mock_parser_cls.return_value.objects = [pkg_obj, dup_pkg_obj, ole_obj, empty_raw_obj]
                office = Office(file_path="dummy.rtf", task_id="7", sha256="0" * 64, options={})
                res = office._parse_rtf(b"{\\rtf1}")

            self.assertEqual(len(res["1"]), 2)
            self.assertEqual(len(res["2"]), 1)
            self.assertEqual(
                office.extracted_files,
                [
                    ("dropper.exe", pkg_bytes),
                    ("object_00000030.package", ole_bytes),
                ],
            )

    def test_parse_continues_when_vba_parser_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "broken_macro.docx"
            sample.write_bytes(b"PK\x03\x04dummy")
            oleid_inst = MagicMock()
            oleid_inst.check.return_value = [SimpleNamespace(value=True, name="Word Document")]

            with (
                patch.object(parse_office, "CUCKOO_ROOT", tmpdir),
                patch.object(parse_office, "HAVE_OLETOOLS", True),
                patch.object(parse_office, "HAVE_XLM_DEOBF", True),
                patch.object(parse_office, "is_rtf", return_value=False),
                patch.object(parse_office, "VBA_Parser", side_effect=RuntimeError("corrupt vba")),
                patch.object(parse_office, "extract_dde", return_value="cmd|'/c echo hi'!A0"),
                patch.object(parse_office.olefile, "isOleFile", return_value=False),
                patch.object(parse_office, "OleID", return_value=oleid_inst),
                patch.object(
                    Office,
                    "_parse_ole_and_ooxml_objects",
                    return_value=([{"relationship": "attachedTemplate", "target": "hxxp://example.invalid", "CVE": "CVE-2017-0199"}], []),
                ),
                patch.object(parse_office, "xlmdeobfuscate", return_value={"Code": ["CALL(...)"]}, create=True),
            ):
                office = Office(file_path=str(sample), task_id="1", sha256="a" * 64, options={})
                office._get_xml_meta = MagicMock(return_value={"SummaryInformation": {"author": "tester"}})
                res = office._parse(str(sample))

            self.assertEqual(res["dde"], "cmd|'/c echo hi'!A0")
            self.assertEqual(res["Metadata"]["HasMacros"], "No")
            self.assertEqual(res["Metadata"]["DocumentType"], "Word Document")
            self.assertEqual(res["XLMMacroDeobfuscator"], {"Code": ["CALL(...)"]})
            self.assertEqual(len(res["external_relationships"]), 1)

    def test_parse_closes_vba_parser_on_extract_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "docm.bin"
            sample.write_bytes(b"dummy")
            mock_vba = MagicMock()
            mock_vba.detect_vba_stomping.return_value = False
            mock_vba.detect_vba_macros.return_value = True
            mock_vba.extract_macros.side_effect = ValueError("broken stream")
            oleid_inst = MagicMock()
            oleid_inst.check.return_value = []

            with (
                patch.object(parse_office, "CUCKOO_ROOT", tmpdir),
                patch.object(parse_office, "HAVE_OLETOOLS", True),
                patch.object(parse_office, "HAVE_VBA2GRAPH", False),
                patch.object(parse_office, "HAVE_XLM_DEOBF", False),
                patch.object(parse_office, "is_rtf", return_value=False),
                patch.object(parse_office, "VBA_Parser", return_value=mock_vba),
                patch.object(parse_office, "extract_dde", return_value=""),
                patch.object(parse_office.olefile, "isOleFile", return_value=False),
                patch.object(parse_office, "OleID", return_value=oleid_inst),
                patch.object(Office, "_parse_ole_and_ooxml_objects", return_value=([], [])),
            ):
                office = Office(file_path=str(sample), task_id="2", sha256="b" * 64, options={})
                office._get_xml_meta = MagicMock(return_value={})
                res = office._parse(str(sample))

            self.assertEqual(res["Metadata"]["HasMacros"], "Yes")
            mock_vba.close.assert_called_once()

    def test_parse_ole_and_ooxml_objects_extracts_rels_and_native_streams(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = b"embedded script payload"
            payload_sha = hashlib.sha256(payload).hexdigest()

            stream_payload = MagicMock()
            stream_link = MagicMock()
            opkg_payload = SimpleNamespace(is_link=False, data=payload, filename="stage2.vbs")
            opkg_link = SimpleNamespace(is_link=True, data=b"linked-ignored", filename="remote.vbs")

            fake_ole = MagicMock()
            fake_ole.listdir.return_value = [
                ["ObjectPool", "_1", "\x01Ole10Native"],
                ["ObjectPool", "_2", "\x01Ole10Native"],
                ["WordDocument"],
            ]
            fake_ole.openstream.side_effect = [stream_payload, stream_link]

            with (
                patch.object(parse_office, "CUCKOO_ROOT", tmpdir),
                patch.object(parse_office.oleobj, "is_zipfile", return_value=True),
                patch.object(parse_office.oleobj, "XmlParser", return_value=object()),
                patch.object(
                    parse_office.oleobj,
                    "find_external_relationships",
                    return_value=[
                        ("oleObject", "mhtml:http://example.invalid/x!y"),
                        ("attachedTemplate", "http://example.invalid/t.dotm"),
                        ("hyperlink", "http://example.invalid/info"),
                    ],
                ),
                patch.object(parse_office.oleobj, "find_customUI", return_value=["http://example.invalid/ui.xml"]),
                patch.object(parse_office.oleobj, "find_ole", return_value=[None, fake_ole]),
                patch.object(parse_office.oleobj, "OleNativeStream", side_effect=[opkg_payload, opkg_link]),
            ):
                office = Office(file_path="dummy.docx", task_id="42", sha256="c" * 64, options={})
                ext_rels, embedded = office._parse_ole_and_ooxml_objects("dummy.docx")

            self.assertEqual(len(ext_rels), 4)
            self.assertEqual(ext_rels[0]["CVE"], "CVE-2021-40444")
            self.assertEqual(ext_rels[1]["CVE"], "CVE-2017-0199")
            self.assertEqual(ext_rels[2]["CVE"], "")
            self.assertEqual(ext_rels[3], {"relationship": "customUI", "target": "http://example.invalid/ui.xml", "CVE": "CVE-2021-42292"})

            self.assertEqual(
                embedded,
                [
                    {
                        "filename": "stage2.vbs",
                        "sha256": payload_sha,
                        "size": len(payload),
                        "stream": "ObjectPool/_1/\\x01Ole10Native",
                    }
                ],
            )
            self.assertEqual(office.extracted_files, [("stage2.vbs", payload)])
            saved_file = Path(tmpdir) / "storage" / "analyses" / "42" / "rtf_objects" / payload_sha
            self.assertTrue(saved_file.is_file())
            self.assertEqual(saved_file.read_bytes(), payload)
            stream_payload.close.assert_called_once()
            stream_link.close.assert_called_once()
            fake_ole.close.assert_called_once()

    def test_parse_vba_stomping_triggers_pcodedmp_fallback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "stomped.doc"
            sample.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")

            mock_vba = MagicMock()
            mock_vba.detect_vba_macros.return_value = False
            mock_vba.detect_vba_stomping.return_value = True
            mock_vba.extract_macros.return_value = []

            def fake_process_project(vba_obj, args, output_file=None):
                self.assertTrue(args.disasmOnly)
                output_file.write("Shell \"http://example.invalid/payload.exe\"\n")

            fake_pcodedmp = SimpleNamespace(processProject=fake_process_project)
            fake_file_inst = MagicMock()
            fake_file_inst.get_yara.side_effect = [[{"name": "macro_yara"}], [{"name": "cape_yara"}]]
            oleid_inst = MagicMock()
            oleid_inst.check.return_value = []

            with (
                patch.object(parse_office, "CUCKOO_ROOT", tmpdir),
                patch.object(parse_office, "HAVE_OLETOOLS", True),
                patch.object(parse_office, "HAVE_PCODEDMP", True),
                patch.object(parse_office, "_pcodedmp", fake_pcodedmp),
                patch.object(parse_office, "HAVE_VBA2GRAPH", False),
                patch.object(parse_office, "HAVE_XLM_DEOBF", False),
                patch.object(parse_office, "is_rtf", return_value=False),
                patch.object(parse_office, "VBA_Parser", return_value=mock_vba),
                patch.object(parse_office, "extract_dde", return_value=""),
                patch.object(parse_office.olefile, "isOleFile", return_value=False),
                patch.object(parse_office, "OleID", return_value=oleid_inst),
                patch.object(parse_office, "File", return_value=fake_file_inst),
                patch.object(parse_office.vbadeobf, "parse_macro", return_value=[("URL", "http://example.invalid/payload.exe")]),
                patch.object(parse_office, "detect_suspicious", return_value=[("Shell", "Runs executable")]),
                patch.object(Office, "_parse_ole_and_ooxml_objects", return_value=([], [])),
            ):
                office = Office(file_path=str(sample), task_id="9", sha256="d" * 64, options={})
                office._get_xml_meta = MagicMock(return_value={})
                res = office._parse(str(sample))

            self.assertEqual(res["Metadata"]["HasMacros"], "Yes")
            self.assertIn(("VBA_Stomping", "VBA source code and P-code differ (possible VBA stomping)"), res["Macro"]["Analysis"]["Suspicious"])
            self.assertIn(("Shell", "Runs executable"), res["Macro"]["Analysis"]["Suspicious"])
            self.assertIn(("URL", "http://example.invalid/payload.exe"), res["Macro"]["Analysis"]["IOCs"])
            self.assertEqual(
                res["Macro"]["info"]["PCode"]["yara_macro"],
                [{"name": "macro_yara"}, {"name": "cape_yara"}],
            )
            self.assertEqual(res["Macro"]["Code"]["PCode"][0][0], "VBA P-Code")
            self.assertIn("http://example.invalid/payload.exe", res["Macro"]["Code"]["PCode"][0][1])
            pcode_dump = Path(tmpdir) / "storage" / "analyses" / "9" / "macros" / "pcode_dump"
            self.assertTrue(pcode_dump.is_file())
            mock_vba.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
