"""Tests for Analyzer and CommandPipeHandler.

Major components not yet tested:
- Analyzer.run()
- Analyzer.complete()
"""

import os
import random
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import analyzer
from analyzer import Analyzer, CommandPipeHandler


class TestModule(unittest.TestCase):
    def test_pid_from_service_name(self):
        # just check it doesn't crash
        _ = analyzer.pid_from_service_name("W32Time")

    def test_get_explorer_pid(self):
        # just check it doesn't crash
        _ = analyzer.get_explorer_pid()

    def test_pids_from_image_names(self):
        pids = analyzer.pids_from_image_names("python.exe")
        # should be at least one Python process running
        self.assertGreaterEqual(len(pids), 1)
        self.assertIn(os.getpid(), pids)

    def test_protected_path_file(self):
        # test protecting bytes-based paths
        with tempfile.NamedTemporaryFile() as ntf:
            with patch("analyzer.PROTECTED_PATH_LIST", []):
                analyzer.add_protected_path(ntf.name.encode())
                self.assertTrue(analyzer.in_protected_path(ntf.name))
                self.assertTrue(analyzer.in_protected_path(ntf.name.encode()))

        # test protecting str-based paths
        with tempfile.NamedTemporaryFile() as ntf:
            with patch("analyzer.PROTECTED_PATH_LIST", []):
                analyzer.add_protected_path(ntf.name)
                self.assertTrue(analyzer.in_protected_path(ntf.name))
                self.assertTrue(analyzer.in_protected_path(ntf.name.encode()))

    def test_in_protected_path_dir(self):
        # test protecting bytes-based paths
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("analyzer.PROTECTED_PATH_LIST", []):
                analyzer.add_protected_path(tmpdir.encode())
                self.assertTrue(analyzer.in_protected_path(tmpdir))
                self.assertTrue(analyzer.in_protected_path(tmpdir.encode()))
                file_in_tmpdir = os.path.join(tmpdir, "random-filename")
                self.assertTrue(analyzer.in_protected_path(file_in_tmpdir))
                self.assertTrue(analyzer.in_protected_path(file_in_tmpdir.encode()))

        # test protecting str-based paths
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("analyzer.PROTECTED_PATH_LIST", []):
                analyzer.add_protected_path(tmpdir)
                self.assertTrue(analyzer.in_protected_path(tmpdir))
                self.assertTrue(analyzer.in_protected_path(tmpdir.encode()))
                file_in_tmpdir = os.path.join(tmpdir, "other-random-filename")
                self.assertTrue(analyzer.in_protected_path(file_in_tmpdir))
                self.assertTrue(analyzer.in_protected_path(file_in_tmpdir.encode()))


class TestAnalyzerInternals(unittest.TestCase):
    def test___init__(self):
        _ = analyzer.Analyzer()

    @patch("analyzer.PipeServer")
    @patch("analyzer.Config")
    @patch("analyzer.init_logging")
    @patch("analyzer.set_clock")
    def test_prepare(self, set_lock, init_logging, config, pipeserver):
        test = analyzer.Analyzer()
        test.prepare()


class TestAnalyzerChoosePackage(unittest.TestCase):
    def setUp(self):
        patch_process = patch("analyzer.Process")
        self.mock_process = patch_process.start()
        self.mock_process.return_value = MagicMock()
        self.addCleanup(patch_process.stop)

    def test_choose_package_shellcode(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "shellcode"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.shellcode", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Shellcode")

    def test_choose_package_Shellcode_x64(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "shellcode_x64"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.shellcode_x64", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Shellcode_x64")

    def test_choose_package_access(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "access"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.access", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "ACCESS")

    def test_choose_package_applet(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "applet"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.applet", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Applet")

    def test_choose_package_archive(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "archive"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.archive", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Archive")

    def test_choose_package_autoit(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "autoit"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.autoit", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "AutoIT")

    def test_choose_package_chm(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "chm"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.chm", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "CHM")

    def test_choose_package_chrome(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "chrome"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.chrome", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Chrome")

    def test_choose_package_chromium(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "chromium"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.chromium", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Chromium")

    def test_choose_package_cpl(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "cpl"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.cpl", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "CPL")

    def test_choose_package_dll(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "dll"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.dll", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Dll")

    def test_choose_package_doc(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "doc"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.doc", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "DOC")

    def test_choose_package_doc2016(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "doc2016"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.doc2016", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "DOC2016")

    def test_choose_package_doc_antivm(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "doc_antivm"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.doc_antivm", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "DOC_ANTIVM")

    def test_choose_package_edge(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "edge"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.edge", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Edge")

    def test_choose_package_eml(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "eml"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.eml", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "EML")

    def test_choose_package_exe(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "exe"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.exe", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Exe")

    def test_choose_package_firefox(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "firefox"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.firefox", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Firefox")

    def test_choose_package_generic(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "generic"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.generic", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Generic")

    def test_choose_package_hta(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "hta"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.hta", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "HTA")

    def test_choose_package_hwp(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "hwp"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.hwp", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "HWP")

    def test_choose_package_ichitaro(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "ichitaro"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.ichitaro", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "ichitaro")

    def test_choose_package_ie(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "ie"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.ie", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "IE")

    def test_choose_package_inf(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "inf"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.inf", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "INF")

    def test_choose_package_inp(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "inp"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.inp", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "INP")

    def test_choose_package_jar(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "jar"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.jar", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Jar")

    def test_choose_package_js(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "js"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.js", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "JS")

    def test_choose_package_js_antivm(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "js_antivm"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.js_antivm", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "JS_ANTIVM")

    def test_choose_package_lnk(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "lnk"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.lnk", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "LNK")

    def test_choose_package_mht(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "mht"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.mht", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "MHT")

    def test_choose_package_msbuild(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "msbuild"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.msbuild", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "MSBUILD")

    def test_choose_package_msg(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "msg"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.msg", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "MSG")

    def test_choose_package_msi(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "msi"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.msi", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Msi")

    def test_choose_package_msix(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "msix"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.msix", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Msix")

    def test_choose_package_nsis(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "nsis"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.nsis", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "NSIS")

    def test_choose_package_ollydbg(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "ollydbg"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.ollydbg", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "OllyDbg")

    def test_choose_package_one(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "one"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.one", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "ONE")

    def test_choose_package_pdf(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "pdf"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.pdf", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "PDF")

    def test_choose_package_ppt(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "ppt"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.ppt", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "PPT")

    def test_choose_package_ppt2016(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "ppt2016"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.ppt2016", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "PPT2007")

    def test_choose_package_ps1(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "ps1"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.ps1", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "PS1")

    def test_choose_package_pub(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "pub"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.pub", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "PUB")

    def test_choose_package_pub2016(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "pub2016"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.pub2016", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "PUB2007")

    def test_choose_package_python(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "python"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.python", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Python")

    def test_choose_package_rar(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "rar"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.rar", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Rar")

    def test_choose_package_reg(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "reg"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.reg", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Reg")

    def test_choose_package_regsvr(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "regsvr"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.regsvr", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Regsvr")

    def test_choose_package_sct(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "sct"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.sct", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "SCT")

    def test_choose_package_service(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "service"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.service", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Service")

    def test_choose_package_service_dll(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "service_dll"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.service_dll", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "ServiceDll")

    def test_choose_package_swf(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "swf"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.swf", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "SWF")

    def test_choose_package_vbejse(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "vbejse"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.vbejse", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "VBSJSE")

    def test_choose_package_vbs(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "vbs"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.vbs", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "VBS")

    def test_choose_package_wsf(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "wsf"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.wsf", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "WSF")

    def test_choose_package_xls(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "xls"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.xls", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "XLS")

    def test_choose_package_xls2016(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "xls2016"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.xls2016", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "XLS2207")

    def test_choose_package_xps(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "xps"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.xps", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Xps")

    def test_choose_package_xslt(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "xslt"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.xslt", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "XSLT")

    def test_choose_package_zip(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "zip"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.zip", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "Zip")

    def test_choose_package_zip_compound(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "zip_compound"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual("modules.packages.zip_compound", pkg_name)
        self.assertEqual(pkg_class.__class__.__name__, "ZipCompound")

    def _assert_autodetected_package(self, file_name, expected_pkg_module, expected_pkg_class_name, file_type="ASCII text"):
        """Helper: auto-detect a package from a file in test_data and assert the result."""
        file_path = os.path.join(os.path.dirname(__file__), "test_data", file_name)
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = ""
        test.config.category = "file"
        test.config.file_name = file_name
        test.config.file_type = file_type
        test.config.exports = ""
        test.target = file_path
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual(f"modules.packages.{expected_pkg_module}", pkg_name)
        self.assertEqual(expected_pkg_class_name, pkg_class.__class__.__name__)

    def test_choose_package_from_eml_file(self):
        """Auto-detect eml package by reading test_email.eml from test_data."""
        self._assert_autodetected_package("test_email.eml", "eml", "EML")

    def test_choose_package_from_python_py_file(self):
        """Auto-detect python package from test_python_file1.py via file extension."""
        self._assert_autodetected_package("test_python_file1.py", "python", "Python")

    def test_choose_package_from_python_data_file(self):
        """Auto-detect python package from test_python_file2.data via #!/usr/bin/env python in content."""
        self._assert_autodetected_package("test_python_file2.data", "python", "Python")


class TestAnalyzerMonitoring(unittest.TestCase):
    def setUp(self):
        patch_sleep = patch("lib.common.defines.KERNEL32.Sleep")
        _ = patch_sleep.start()
        self.addCleanup(patch_sleep.stop)
        patch_call = patch("subprocess.call")
        self.call = patch_call.start()
        self.addCleanup(patch_call.stop)
        self.analyzer = Analyzer()
        self.pipe_handler = CommandPipeHandler(self.analyzer)
        # Since the CommandPipeHandler.ignore_list is a class variable,
        # we reset it between tests, so we get a fresh start.
        self.pipe_handler.ignore_list = dict(pid=[])

    def test_can_instantiate(self):
        self.assertIsInstance(self.analyzer, Analyzer)
        self.assertIsInstance(self.pipe_handler, CommandPipeHandler)

    def test_handle_loaded(self):
        random_pid = random.randint(1, 99999999)
        pending_process = MagicMock()
        ana = self.analyzer
        with (
            patch("analyzer.INJECT_LIST", [random_pid]),
            patch("analyzer.INJECT_IDENTITIES", {random_pid: 100}),
            patch("analyzer.INJECT_PROCESSES", {random_pid: pending_process}),
            patch("analyzer.MONITORED_PROCESSES", {}) as monitored,
        ):
            self.assertEqual(1, len(analyzer.INJECT_LIST))
            self.pipe_handler._handle_loaded(data=str(random_pid))
            self.assertEqual(0, len(analyzer.INJECT_LIST))
            self.assertEqual({random_pid: pending_process}, monitored)
        pending_process.close.assert_not_called()
        self.assertIn(random_pid, ana.process_list.pids)

    def test_handle_loaded_rejects_stale_process_identity(self):
        pending_process = MagicMock()
        with (
            patch("analyzer.INJECT_LIST", [4242]) as pending,
            patch("analyzer.INJECT_IDENTITIES", {4242: 200}),
            patch("analyzer.INJECT_PROCESSES", {4242: pending_process}),
            patch("analyzer.MONITORED_PROCESSES", {}) as monitored,
        ):
            self.pipe_handler._handle_loaded(data="4242,i:100")

            self.assertEqual([4242], pending)
        pending_process.close.assert_not_called()
        self.assertEqual({}, monitored)
        self.assertNotIn(4242, self.analyzer.process_list.pids)

    def test_handle_loaded_accepts_matching_process_identity(self):
        pending_process = MagicMock()
        with (
            patch("analyzer.INJECT_LIST", [4242]) as pending,
            patch("analyzer.INJECT_IDENTITIES", {4242: 100}),
            patch("analyzer.INJECT_PROCESSES", {4242: pending_process}),
            patch("analyzer.MONITORED_PROCESSES", {}) as monitored,
        ):
            self.pipe_handler._handle_loaded(data="4242,i:100")

            self.assertEqual([], pending)
            self.assertEqual({4242: pending_process}, monitored)
        pending_process.close.assert_not_called()
        self.assertIn(4242, self.analyzer.process_list.pids)

    def test_handle_loaded_rejects_malformed_process_identity(self):
        pending_process = MagicMock()
        with (
            patch("analyzer.INJECT_LIST", [4242]) as pending,
            patch("analyzer.INJECT_IDENTITIES", {4242: 100}),
            patch("analyzer.INJECT_PROCESSES", {4242: pending_process}),
            patch("analyzer.MONITORED_PROCESSES", {}) as monitored,
        ):
            self.pipe_handler._handle_loaded(data="4242,i:-- UNKNOWN FORMAT STRING -- lu")

            self.assertEqual([4242], pending)
            self.assertEqual({}, monitored)
        pending_process.close.assert_not_called()
        self.assertNotIn(4242, self.analyzer.process_list.pids)

    def test_handle_loaded_accepts_legacy_track_field(self):
        pending_process = MagicMock()
        with (
            patch("analyzer.INJECT_LIST", [4242]) as pending,
            patch("analyzer.INJECT_IDENTITIES", {4242: 100}),
            patch("analyzer.INJECT_PROCESSES", {4242: pending_process}),
            patch("analyzer.MONITORED_PROCESSES", {}) as monitored,
        ):
            self.pipe_handler._handle_loaded(data="4242,1")

            self.assertEqual([], pending)
            self.assertEqual({4242: pending_process}, monitored)
        pending_process.close.assert_not_called()
        self.assertIn(4242, self.analyzer.process_list.pids)

    def test_duplicate_loaded_keeps_monitored_process_handle_open(self):
        monitored_process = MagicMock()
        self.analyzer.process_list.add_pid(4242)
        with (
            patch("analyzer.INJECT_LIST", []),
            patch("analyzer.INJECT_IDENTITIES", {}),
            patch("analyzer.INJECT_PROCESSES", {}),
            patch("analyzer.MONITORED_PROCESSES", {4242: monitored_process}) as monitored,
        ):
            self.pipe_handler._handle_loaded(data="4242,i:100")

            self.assertEqual({4242: monitored_process}, monitored)
        monitored_process.close.assert_not_called()

    def test_handle_kterminate(self):
        ana = self.analyzer
        random_pid = random.randint(1, 99999999)
        ana.process_list.pids.append(random_pid)
        self.assertEqual(1, len(ana.process_list.pids))
        self.pipe_handler._handle_kterminate(data=str(random_pid))
        self.assertEqual(0, len(ana.process_list.pids))

    def test_handle_kterminate_releases_pending_process(self):
        pending_process = MagicMock()
        pending_process.is_alive.return_value = False
        with (
            patch("analyzer.INJECT_LIST", [4242]) as pending,
            patch("analyzer.INJECT_IDENTITIES", {4242: 100}),
            patch("analyzer.INJECT_PROCESSES", {4242: pending_process}),
        ):
            self.pipe_handler._handle_kterminate(data="4242")

            self.assertEqual([], pending)
        pending_process.close.assert_called_once()

    def test_stale_kterminate_does_not_release_live_pending_process(self):
        pending_process = MagicMock()
        pending_process.is_alive.return_value = True
        with (
            patch("analyzer.INJECT_LIST", [4242]) as pending,
            patch("analyzer.INJECT_IDENTITIES", {4242: 100}),
            patch("analyzer.INJECT_PROCESSES", {4242: pending_process}),
        ):
            self.pipe_handler._handle_kterminate(data="4242")

            self.assertEqual([4242], pending)
        pending_process.close.assert_not_called()

    def test_stale_kterminate_does_not_untrack_live_monitored_process(self):
        monitored_process = MagicMock()
        monitored_process.is_alive.return_value = True
        self.analyzer.process_list.add_pid(4242)
        with patch("analyzer.MONITORED_PROCESSES", {4242: monitored_process}):
            self.pipe_handler._handle_kterminate(data="4242")

        self.assertIn(4242, self.analyzer.process_list.pids)
        monitored_process.close.assert_not_called()

    def test_kterminate_releases_dead_monitored_process(self):
        monitored_process = MagicMock()
        monitored_process.is_alive.return_value = False
        self.analyzer.process_list.add_pid(4242)
        with patch("analyzer.MONITORED_PROCESSES", {4242: monitored_process}):
            self.pipe_handler._handle_kterminate(data="4242")

        self.assertNotIn(4242, self.analyzer.process_list.pids)
        monitored_process.close.assert_called_once()

    def test_kill_keeps_process_tracked_until_termination_is_confirmed(self):
        monitored_process = MagicMock()
        self.analyzer.process_list.add_pid(4242)
        with patch("analyzer.MONITORED_PROCESSES", {4242: monitored_process}):
            self.pipe_handler._handle_kill(data="4242")

        self.assertIn(4242, self.analyzer.process_list.pids)
        monitored_process.close.assert_not_called()

    def test_kill_retains_legacy_process_until_termination_is_confirmed(self):
        monitored_process = MagicMock()
        self.analyzer.process_list.add_pid(4242)
        with (
            patch("analyzer.INJECT_PROCESSES", {}),
            patch("analyzer.MONITORED_PROCESSES", {}) as monitored,
            patch.object(self.pipe_handler, "_open_process_instance", return_value=(monitored_process, 100)),
        ):
            self.pipe_handler._handle_kill(data="4242")

            self.assertEqual({4242: monitored_process}, monitored)
        self.assertIn(4242, self.analyzer.process_list.pids)
        monitored_process.close.assert_not_called()

    def test_kill_ignores_untracked_process(self):
        with patch.object(self.pipe_handler, "_open_process_instance") as open_process:
            self.pipe_handler._handle_kill(data="4242")

        open_process.assert_not_called()

    def test_pending_reaper_releases_process_that_exited_before_loaded(self):
        pending_process = MagicMock()
        pending_process.is_alive.return_value = False
        with (
            patch("analyzer.INJECT_LIST", [4242]) as pending,
            patch("analyzer.INJECT_IDENTITIES", {4242: 100}),
            patch("analyzer.INJECT_PROCESSES", {4242: pending_process}),
        ):
            self.analyzer.reap_pending_injections()

            self.assertEqual([], pending)
        pending_process.close.assert_called_once()

    def test_pending_reaper_keeps_live_process(self):
        pending_process = MagicMock()
        pending_process.is_alive.return_value = True
        with (
            patch("analyzer.INJECT_LIST", [4242]) as pending,
            patch("analyzer.INJECT_IDENTITIES", {4242: 100}),
            patch("analyzer.INJECT_PROCESSES", {4242: pending_process}),
        ):
            self.analyzer.reap_pending_injections()

            self.assertEqual([4242], pending)
        pending_process.close.assert_not_called()

    def test_monitored_reaper_releases_dead_process(self):
        monitored_process = MagicMock()
        monitored_process.is_alive.return_value = False
        self.analyzer.process_list.add_pid(4242)
        with patch("analyzer.MONITORED_PROCESSES", {4242: monitored_process}) as monitored:
            self.analyzer.reap_monitored_processes()

            self.assertEqual({}, monitored)
        self.assertNotIn(4242, self.analyzer.process_list.pids)
        monitored_process.close.assert_called_once()

    @patch("analyzer.Process")
    def test_handle_kprocess(self, mock_process):
        ana = self.analyzer
        random_pid = random.randint(1, 99999999)
        self.assertEqual(0, len(ana.process_list.pids))
        self.pipe_handler._handle_kprocess(data=str(random_pid))
        self.assertEqual(1, len(ana.process_list.pids))
        self.assertIn(random_pid, ana.process_list.pids)
        mock_process.assert_called_once()

    def test_handle_ksubvert(self):
        ana = self.analyzer
        random_pid1 = random.randint(1, 99999999)
        random_pid2 = random.randint(1, 99999999)
        random_pid3 = random.randint(1, 99999999)
        ana.process_list.pids = [random_pid1, random_pid2, random_pid3]
        self.pipe_handler._handle_ksubvert(data=None)
        self.assertEqual(0, len(ana.process_list.pids))

    @patch("analyzer.Process")
    @patch("analyzer.get_explorer_pid")
    def test_handle_shell(self, mock_get_explorer_pid, mock_process):
        ana = self.analyzer
        random_pid = random.randint(1, 99999999)
        mock_get_explorer_pid.return_value = random_pid
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.pipe_handler._handle_shell(data=None)
        self.assertEqual(1, len(ana.CRITICAL_PROCESS_LIST))
        self.assertIn(random_pid, ana.CRITICAL_PROCESS_LIST)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        mock_process.assert_called_once()

    @patch("analyzer.pid_from_service_name")
    @patch("analyzer.Process")
    def test_handle_interop(self, mock_process, mock_pid_from_service_name):
        mock_process.return_value = MagicMock()
        random_pid = random.randint(1, 99999999)
        mock_pid_from_service_name.return_value = random_pid
        ana = self.analyzer
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.pipe_handler._handle_interop(None)
        self.assertEqual(1, len(ana.CRITICAL_PROCESS_LIST))
        self.assertTrue(ana.MONITORED_DCOM)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        self.assertIn(random_pid, ana.CRITICAL_PROCESS_LIST)
        mock_pid_from_service_name.assert_called_once()
        self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_handle_interop_already(self, mock_process):
        """If dcom process already monitored, do nothing."""
        ana = self.analyzer
        ana.MONITORED_DCOM = True
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.pipe_handler._handle_interop(None)
        # No change to process list or last inject time
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()
        self.call.assert_not_called()

    @patch("analyzer.pid_from_service_name")
    @patch("analyzer.Process")
    def test_handle_interop_timed_out(self, mock_process, mock_pid_from_service_name):
        ana = self.analyzer
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        with patch("analyzer.ANALYSIS_TIMED_OUT", True):
            self.pipe_handler._handle_interop(None)
        # No change to process list, DCOM, or last inject time
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_pid_from_service_name.assert_not_called()
        mock_process.assert_not_called()
        self.call.assert_not_called()

    @patch("analyzer.pids_from_image_names", return_value=[])
    @patch("analyzer.subprocess.run")
    @patch("analyzer.pid_from_service_name")
    def test_handle_wmi(self, mock_pid_from_service_name, mock_run, mock_pids_from_image_names):
        random_pid1 = random.randint(1, 99999999)
        random_pid2 = random.randint(1, 99999999)
        mock_pid_from_service_name.side_effect = [random_pid1, random_pid2]
        ana = self.analyzer
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_WMI)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.pipe_handler._handle_wmi(None)
        self.assertEqual(2, len(ana.CRITICAL_PROCESS_LIST))
        self.assertTrue(ana.MONITORED_WMI)
        self.assertTrue(ana.MONITORED_DCOM)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        self.assertIn(random_pid1, ana.CRITICAL_PROCESS_LIST)
        self.assertIn(random_pid2, ana.CRITICAL_PROCESS_LIST)
        mock_run.assert_called_once_with(
            [
                analyzer.os.path.join(analyzer.os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe"),
                str(analyzer.Path.cwd()),
                "/grant",
                "*S-1-5-20:(OI)(CI)(RX)",
                "/t",
                "/c",
                "/q",
            ],
            capture_output=True,
            text=True,
        )
        mock_pids_from_image_names.assert_called_once_with(["WmiPrvSE.exe"])

    @patch("analyzer.pids_from_image_names", return_value=[])
    @patch("analyzer.subprocess.run", side_effect=FileNotFoundError("icacls.exe"))
    @patch("analyzer.pid_from_service_name", return_value=None)
    def test_handle_wmi_continues_when_icacls_is_unavailable(
        self, mock_pid_from_service_name, mock_run, mock_pids_from_image_names
    ):
        self.pipe_handler._handle_wmi(None)

        mock_run.assert_called_once()
        mock_pids_from_image_names.assert_called_once_with(["WmiPrvSE.exe"])

    @patch("analyzer.pids_from_image_names")
    @patch("analyzer.subprocess.run")
    @patch("analyzer.pid_from_service_name")
    @patch("analyzer.process_instance_id", return_value=100)
    @patch("analyzer.Process")
    def test_handle_wmi_injects_existing_provider_hosts(
        self, mock_process, mock_process_instance_id, mock_pid_from_service_name, mock_run, mock_pids_from_image_names
    ):
        dcom_pid = random.randint(1, 99999999)
        winmgmt_pid = random.randint(1, 99999999)
        provider_pids = [random.randint(1, 99999999), random.randint(1, 99999999)]
        mock_pid_from_service_name.side_effect = [dcom_pid, winmgmt_pid]
        mock_pids_from_image_names.return_value = provider_pids

        with (
            patch("analyzer.INJECT_LIST", []) as inject_list,
            patch("analyzer.INJECT_IDENTITIES", {}),
            patch("analyzer.INJECT_PROCESSES", {}),
        ):
            self.pipe_handler._handle_wmi(None)
            self.assertEqual(set(provider_pids), set(inject_list))

        mock_pids_from_image_names.assert_called_once_with(["WmiPrvSE.exe"])
        self.assertEqual(
            {dcom_pid, winmgmt_pid, *provider_pids},
            set(self.analyzer.CRITICAL_PROCESS_LIST),
        )
        self.assertEqual(4, mock_process.call_count)
        mock_run.assert_called_once()

    @patch("analyzer.pids_from_image_names")
    @patch("analyzer.subprocess.run")
    @patch("analyzer.pid_from_service_name", return_value=None)
    @patch("analyzer.process_instance_id", return_value=100)
    @patch("analyzer.Process")
    def test_handle_wmi_does_not_reinject_announced_provider(
        self, mock_process, mock_process_instance_id, mock_pid_from_service_name, mock_run, mock_pids_from_image_names
    ):
        provider_pid = random.randint(1, 99999999)
        mock_pids_from_image_names.return_value = [provider_pid]

        with (
            patch("analyzer.INJECT_LIST", [provider_pid]),
            patch("analyzer.INJECT_IDENTITIES", {provider_pid: 100}),
            patch("analyzer.INJECT_PROCESSES", {}),
        ):
            self.pipe_handler._handle_wmi(None)

        mock_process.assert_not_called()
        mock_run.assert_called_once()

    @patch("analyzer.pids_from_image_names", return_value=[4242])
    @patch("analyzer.subprocess.run")
    @patch("analyzer.pid_from_service_name", return_value=None)
    def test_handle_wmi_uses_atomic_reservation(self, mock_pid_from_service_name, mock_run, mock_pids_from_image_names):
        with patch.object(self.pipe_handler, "_reserve_injection", return_value=None) as reserve:
            self.pipe_handler._handle_wmi(None)

        reserve.assert_called_once_with(4242)

    @patch("analyzer.pids_from_image_names", return_value=[4242, 4343])
    @patch("analyzer.subprocess.run")
    @patch("analyzer.pid_from_service_name", return_value=None)
    @patch("analyzer.process_instance_id", return_value=100)
    @patch("analyzer.Process")
    def test_handle_wmi_releases_failed_provider_and_continues(
        self, mock_process, mock_process_instance_id, mock_pid_from_service_name, mock_run, mock_pids_from_image_names
    ):
        failed_process = MagicMock()
        failed_process.h_process = 1
        failed_process.inject.return_value = False
        injected_process = MagicMock()
        injected_process.h_process = 2
        injected_process.inject.return_value = True
        mock_process.side_effect = [failed_process, injected_process]

        with (
            patch("analyzer.INJECT_LIST", []) as pending,
            patch("analyzer.INJECT_IDENTITIES", {}),
            patch("analyzer.INJECT_PROCESSES", {}),
        ):
            self.pipe_handler._handle_wmi(None)

            self.assertEqual([4343], pending)
        failed_process.close.assert_called_once()
        injected_process.close.assert_not_called()
        self.assertEqual([4343], self.analyzer.CRITICAL_PROCESS_LIST)

    @patch("analyzer.pids_from_image_names", return_value=[4242])
    @patch("analyzer.subprocess.run")
    @patch("analyzer.pid_from_service_name")
    def test_handle_wmi_already_does_not_rescan_without_retry(
        self, mock_pid_from_service_name, mock_run, mock_pids_from_image_names
    ):
        ana = self.analyzer
        ana.MONITORED_WMI = True
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.pipe_handler._handle_wmi(None)
        # Should be no change to DCOM or last inject time
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_pid_from_service_name.assert_not_called()
        mock_run.assert_not_called()
        mock_pids_from_image_names.assert_not_called()
        self.call.assert_not_called()

    @patch("analyzer.pids_from_image_names", return_value=[4242])
    @patch("analyzer.pid_from_service_name")
    def test_handle_wmi_rescans_after_retry_delay(self, mock_pid_from_service_name, mock_pids_from_image_names):
        self.analyzer.MONITORED_WMI = True
        self.analyzer.WMI_PROVIDER_RETRY_AT = 10

        with patch("analyzer.timeit.default_timer", return_value=11), patch.object(
            self.pipe_handler, "_reserve_injection", return_value=None
        ) as reserve:
            self.pipe_handler._handle_wmi(None)

        reserve.assert_called_once_with(4242)
        mock_pid_from_service_name.assert_not_called()

    def test_handle_wmi_timed_out(self):
        ana = self.analyzer
        self.assertFalse(ana.MONITORED_WMI)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        with patch("analyzer.ANALYSIS_TIMED_OUT", True):
            self.pipe_handler._handle_wmi(data=None)
        # Should be no change to DCOM, WMI, or last inject time
        self.assertFalse(ana.MONITORED_WMI)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.call.assert_not_called()

    @patch("analyzer.Process")
    @patch("analyzer.pid_from_service_name")
    def test_handle_tasksched(self, mock_pid_from_service_name, mock_process):
        random_pid = random.randint(1, 99999999)
        mock_pid_from_service_name.return_value = random_pid
        ana = self.analyzer
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_TASKSCHED)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.pipe_handler._handle_tasksched(data=None)
        self.assertEqual(1, len(ana.CRITICAL_PROCESS_LIST))
        self.assertIn(random_pid, ana.CRITICAL_PROCESS_LIST)
        self.assertTrue(ana.MONITORED_TASKSCHED)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        self.call.assert_called()
        mock_process.assert_called_once()

    def test_handle_tasksched_timed_out(self):
        ana = self.analyzer
        self.assertFalse(ana.MONITORED_TASKSCHED)
        self.assertIsNone(ana.LASTINJECT_TIME)
        with patch("analyzer.ANALYSIS_TIMED_OUT", True):
            self.pipe_handler._handle_tasksched(data=None)
        # Should be no change to TASKSCHED or last inject time
        self.assertFalse(ana.MONITORED_TASKSCHED)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.call.assert_not_called()

    @patch("analyzer.pid_from_service_name")
    def test_handle_tasksched_already(self, mock_pid_from_service_name):
        ana = self.analyzer
        ana.MONITORED_TASKSCHED = True
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.pipe_handler._handle_tasksched(data=None)
        # Should be no change to last inject time
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.call.assert_not_called()
        mock_pid_from_service_name.assert_not_called()

    @patch("analyzer.pid_from_service_name")
    def test_handle_bits(self, mock_pid_from_service_name):
        random_pid1 = random.randint(1, 99999999)
        random_pid2 = random.randint(1, 99999999)
        mock_pid_from_service_name.side_effect = [random_pid1, random_pid2]
        ana = self.analyzer
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_BITS)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.pipe_handler._handle_bits(data=None)
        self.assertEqual(2, len(ana.CRITICAL_PROCESS_LIST))
        self.assertTrue(ana.MONITORED_BITS)
        self.assertTrue(ana.MONITORED_DCOM)
        self.assertIsNotNone(ana.LASTINJECT_TIME)

    def test_handle_bits_already(self):
        ana = self.analyzer
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        ana.MONITORED_BITS = True
        self.pipe_handler._handle_bits(data=None)
        # Should be no change to DCOM or last inject time
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.call.assert_not_called()

    def test_handle_bits_timed_out(self):
        ana = self.analyzer
        self.assertFalse(ana.MONITORED_BITS)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        with patch("analyzer.ANALYSIS_TIMED_OUT", True):
            self.pipe_handler._handle_bits(data=None)
        # Should be no change to DCOM, BITS, or last inject time
        self.assertFalse(ana.MONITORED_BITS)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_handle_service(self, mock_process):
        ana = self.analyzer
        # Relies on SERVICES_PID being set.
        ana.SERVICES_PID = 12345
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_SERVICES)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.pipe_handler._handle_service(servname=b"random-service-name")
        self.assertEqual(1, len(ana.CRITICAL_PROCESS_LIST))
        self.assertTrue(ana.MONITORED_SERVICES)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        mock_process.assert_called_once()
        self.call.assert_called_once()

    @patch("analyzer.Process")
    def test_handle_service_already(self, mock_process):
        ana = self.analyzer
        self.assertIsNone(ana.LASTINJECT_TIME)
        ana.MONITORED_SERVICES = True
        self.pipe_handler._handle_service(servname=b"any-name-can-go-here")
        # Should be no change to process list or last inject time
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()
        # It still wil call "sc config"
        self.call.assert_called_once()

    @patch("analyzer.Process")
    def test_handle_service_timed_out(self, mock_process):
        ana = self.analyzer
        self.assertFalse(ana.MONITORED_SERVICES)
        self.assertIsNone(ana.LASTINJECT_TIME)
        with patch("analyzer.ANALYSIS_TIMED_OUT", True):
            self.pipe_handler._handle_service(servname="random-service-name")
        # Should be no change to MONITORED_SERVICES or last inject time
        self.assertFalse(ana.MONITORED_SERVICES)
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()
        self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_inject_process(self, mock_process):
        random_pid = random.randint(1, 99999999)
        ana = self.analyzer
        self.assertEqual(0, len(ana.process_list.pids))
        self.assertEqual(0, len(self.pipe_handler.ignore_list["pid"]))
        self.pipe_handler._inject_process(process_id=random_pid, thread_id=None, mode=None)
        self.assertEqual(1, len(ana.process_list.pids))
        self.assertIn(random_pid, ana.process_list.pids)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        mock_process.assert_called_once()
        self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_inject_process_self(self, mock_process):
        """If _inject_process is called with the pid of the analyzer, do nothing."""
        random_pid = random.randint(1, 99999999)
        ana = self.analyzer
        ana.pid = random_pid
        self.assertEqual(0, len(self.pipe_handler.ignore_list["pid"]))
        self.pipe_handler._inject_process(process_id=random_pid, thread_id=None, mode=None)
        self.assertEqual(1, len(self.pipe_handler.ignore_list["pid"]))
        self.assertIn(random_pid, self.pipe_handler.ignore_list["pid"])
        # Should be no change to last inject time
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()
        self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_inject_process_already(self, mock_process):
        """If _inject_process is called with a pid we are already monitoring, do nothing."""
        random_pid = random.randint(1, 99999999)
        ana = self.analyzer
        ana.process_list.pids.append(random_pid)
        self.assertEqual(0, len(self.pipe_handler.ignore_list["pid"]))
        self.pipe_handler._inject_process(process_id=random_pid, thread_id=None, mode=None)
        self.assertEqual(1, len(self.pipe_handler.ignore_list["pid"]))
        self.assertIn(random_pid, self.pipe_handler.ignore_list["pid"])
        # Should be no change to last inject time
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()
        self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_inject_process_already_notrack(self, mock_process):
        """If _inject_process is called with a pid on the notrack list, move it to the track list.

        Do nothing else.
        """
        random_pid = random.randint(1, 99999999)
        ana = self.analyzer
        ana.process_list.pids_notrack.append(random_pid)
        self.assertEqual(0, len(self.pipe_handler.ignore_list["pid"]))
        self.assertEqual(0, len(ana.process_list.pids))
        self.pipe_handler._inject_process(process_id=random_pid, thread_id=None, mode=None)
        self.assertEqual(1, len(self.pipe_handler.ignore_list["pid"]))
        self.assertIn(random_pid, self.pipe_handler.ignore_list["pid"])
        self.assertIn(random_pid, ana.process_list.pids)
        self.assertEqual(0, len(ana.process_list.pids_notrack))
        self.assertEqual(1, len(ana.process_list.pids))
        # Should be no change to last inject time
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()
        self.call.assert_not_called()

    @patch("analyzer.process_instance_id", return_value=100)
    @patch("analyzer.Process")
    def test_handle_process(self, mock_process, mock_process_instance_id):
        ana = self.analyzer
        ana.config = MagicMock()
        self.assertEqual(0, ana.NUM_INJECTED)
        # TODO add a couple of mocks
        random_pid = random.randint(1, 99999999)
        random_tid = random.randint(1, 9999999)
        data = bytes(f"{random_pid},{random_tid}".encode())
        # This produces something like b"910271,1819029"
        with (
            patch("analyzer.INJECT_LIST", []),
            patch("analyzer.INJECT_IDENTITIES", {}),
            patch("analyzer.INJECT_PROCESSES", {}),
        ):
            self.pipe_handler._handle_process(data=data)
            self.assertEqual(1, len(analyzer.INJECT_LIST))
            self.assertIn(random_pid, analyzer.INJECT_LIST)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        mock_process.assert_called_once()
        self.assertEqual(1, ana.NUM_INJECTED)

    @patch("analyzer.process_instance_id", return_value=100)
    @patch("analyzer.Process")
    def test_handle_process_does_not_repeat_pending_injection(self, mock_process, mock_process_instance_id):
        random_pid = random.randint(1, 99999999)
        random_tid = random.randint(1, 9999999)
        data = bytes(f"{random_pid},{random_tid}".encode())

        with (
            patch("analyzer.INJECT_LIST", [random_pid]),
            patch("analyzer.INJECT_IDENTITIES", {random_pid: 100}),
            patch("analyzer.INJECT_PROCESSES", {}),
        ):
            self.pipe_handler._handle_process(data=data)

        mock_process.assert_not_called()
        self.assertIsNone(self.analyzer.LASTINJECT_TIME)
        self.assertEqual(0, self.analyzer.NUM_INJECTED)

    def test_handle_process_uses_atomic_reservation(self):
        with patch.object(self.pipe_handler, "_reserve_injection", return_value=None) as reserve:
            self.pipe_handler._handle_process(data=b"4242,101")

        reserve.assert_called_once_with(4242, 101, include_notrack=False)

    @patch("analyzer.process_instance_id", return_value=100)
    @patch("analyzer.Process")
    def test_handle_process_releases_failed_injection(self, mock_process, mock_process_instance_id):
        self.analyzer.config = MagicMock(category="file")
        process = mock_process.return_value
        process.h_process = 1
        process.get_filepath.return_value = r"C:\malware.exe"
        process.inject.return_value = False

        with (
            patch("analyzer.INJECT_LIST", []) as pending,
            patch("analyzer.INJECT_IDENTITIES", {}),
            patch("analyzer.INJECT_PROCESSES", {}),
        ):
            self.pipe_handler._handle_process(data=b"4242,101")

            self.assertEqual([], pending)
        process.close.assert_called_once()
        self.assertEqual(0, self.analyzer.NUM_INJECTED)
