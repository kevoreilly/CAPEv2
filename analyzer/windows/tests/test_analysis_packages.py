"""Basic import/instantiate test for analysis packages."""

import importlib
import inspect
import unittest

from lib.common.abstracts import Package


class TestAnalysisPackages(unittest.TestCase):
    def class_from_analysis_package(self, module_name):
        module = importlib.import_module(module_name)
        members = inspect.getmembers(module)
        member_classes = [m[1] for m in members if inspect.isclass(m[1])]
        pkg_classes = [c for c in member_classes if issubclass(c, Package) and c != Package]
        self.assertEqual(1, len(pkg_classes))
        return pkg_classes[0]

    def test_choose_package_Shellcode_Unpacker(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Shellcode-Unpacker")
        pkg_class()

    def test_Shellcode(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Shellcode")
        pkg_class()

    def test_Shellcode_x64(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Shellcode_x64")
        pkg_class()

    def test_Unpacker(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker")
        pkg_class()

    def test_Unpacker_dll(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker_dll")
        pkg_class()

    def test_Unpacker_js(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker_js")
        pkg_class()

    def test_Unpacker_ps1(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker_ps1")
        pkg_class()

    def test_Unpacker_regsvr(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker_regsvr")
        pkg_class()

    def test_Unpacker_zip(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker_zip")
        pkg_class()

    def test_access(self):
        pkg_class = self.class_from_analysis_package("modules.packages.access")
        pkg_class()

    def test_applet(self):
        pkg_class = self.class_from_analysis_package("modules.packages.applet")
        pkg_class()

    def test_archive(self):
        pkg_class = self.class_from_analysis_package("modules.packages.archive")
        pkg_class()

    def test_autoit(self):
        pkg_class = self.class_from_analysis_package("modules.packages.autoit")
        pkg_class()

    def test_chm(self):
        pkg_class = self.class_from_analysis_package("modules.packages.chm")
        pkg_class()

    def test_chrome(self):
        pkg_class = self.class_from_analysis_package("modules.packages.chrome")
        pkg_class()

    def test_chromium(self):
        pkg_class = self.class_from_analysis_package("modules.packages.chromium")
        pkg_class()

    def test_cpl(self):
        pkg_class = self.class_from_analysis_package("modules.packages.cpl")
        pkg_class()

    def test_dll(self):
        pkg_class = self.class_from_analysis_package("modules.packages.dll")
        pkg_class()

    def test_doc(self):
        pkg_class = self.class_from_analysis_package("modules.packages.doc")
        pkg_class()

    def test_doc2016(self):
        pkg_class = self.class_from_analysis_package("modules.packages.doc2016")
        pkg_class()

    def test_doc_antivm(self):
        pkg_class = self.class_from_analysis_package("modules.packages.doc_antivm")
        pkg_class()

    def test_edge(self):
        pkg_class = self.class_from_analysis_package("modules.packages.edge")
        pkg_class()

    def test_eml(self):
        pkg_class = self.class_from_analysis_package("modules.packages.eml")
        pkg_class()

    def test_exe(self):
        pkg_class = self.class_from_analysis_package("modules.packages.exe")
        pkg_class()

    def test_firefox(self):
        pkg_class = self.class_from_analysis_package("modules.packages.firefox")
        pkg_class()

    def test_generic(self):
        pkg_class = self.class_from_analysis_package("modules.packages.generic")
        pkg_class()

    def test_hta(self):
        pkg_class = self.class_from_analysis_package("modules.packages.hta")
        pkg_class()

    def test_hwp(self):
        pkg_class = self.class_from_analysis_package("modules.packages.hwp")
        pkg_class()

    def test_ichitaro(self):
        pkg_class = self.class_from_analysis_package("modules.packages.ichitaro")
        pkg_class()

    def test_ie(self):
        pkg_class = self.class_from_analysis_package("modules.packages.ie")
        pkg_class()

    def test_inf(self):
        pkg_class = self.class_from_analysis_package("modules.packages.inf")
        pkg_class()

    def test_inp(self):
        pkg_class = self.class_from_analysis_package("modules.packages.inp")
        pkg_class()

    def test_jar(self):
        pkg_class = self.class_from_analysis_package("modules.packages.jar")
        pkg_class()

    def test_js(self):
        pkg_class = self.class_from_analysis_package("modules.packages.js")
        pkg_class()

    def test_js_antivm(self):
        pkg_class = self.class_from_analysis_package("modules.packages.js_antivm")
        pkg_class()

    def test_lnk(self):
        pkg_class = self.class_from_analysis_package("modules.packages.lnk")
        pkg_class()

    def test_mht(self):
        pkg_class = self.class_from_analysis_package("modules.packages.mht")
        pkg_class()

    def test_msbuild(self):
        pkg_class = self.class_from_analysis_package("modules.packages.msbuild")
        pkg_class()

    def test_msg(self):
        pkg_class = self.class_from_analysis_package("modules.packages.msg")
        pkg_class()

    def test_msi(self):
        pkg_class = self.class_from_analysis_package("modules.packages.msi")
        pkg_class()

    def test_msix(self):
        pkg_class = self.class_from_analysis_package("modules.packages.msix")
        pkg_class()

    def test_nsis(self):
        pkg_class = self.class_from_analysis_package("modules.packages.nsis")
        pkg_class()

    def test_ollydbg(self):
        pkg_class = self.class_from_analysis_package("modules.packages.ollydbg")
        pkg_class()

    def test_one(self):
        pkg_class = self.class_from_analysis_package("modules.packages.one")
        pkg_class()

    def test_pdf(self):
        pkg_class = self.class_from_analysis_package("modules.packages.pdf")
        pkg_class()

    def test_ppt(self):
        pkg_class = self.class_from_analysis_package("modules.packages.ppt")
        pkg_class()

    def test_ppt2016(self):
        pkg_class = self.class_from_analysis_package("modules.packages.ppt2016")
        pkg_class()

    def test_ps1(self):
        pkg_class = self.class_from_analysis_package("modules.packages.ps1")
        pkg_class()

    def test_pub(self):
        pkg_class = self.class_from_analysis_package("modules.packages.pub")
        pkg_class()

    def test_pub2016(self):
        pkg_class = self.class_from_analysis_package("modules.packages.pub2016")
        pkg_class()

    def test_python(self):
        pkg_class = self.class_from_analysis_package("modules.packages.python")
        pkg_class()

    def test_rar(self):
        pkg_class = self.class_from_analysis_package("modules.packages.rar")
        pkg_class()

    def test_reg(self):
        pkg_class = self.class_from_analysis_package("modules.packages.reg")
        pkg_class()

    def test_regsvr(self):
        pkg_class = self.class_from_analysis_package("modules.packages.regsvr")
        pkg_class()

    def test_sct(self):
        pkg_class = self.class_from_analysis_package("modules.packages.sct")
        pkg_class()

    def test_service(self):
        pkg_class = self.class_from_analysis_package("modules.packages.service")
        pkg_class()

    def test_service_dll(self):
        pkg_class = self.class_from_analysis_package("modules.packages.service_dll")
        pkg_class()

    def test_swf(self):
        pkg_class = self.class_from_analysis_package("modules.packages.swf")
        pkg_class()

    def test_vawtrak(self):
        pkg_class = self.class_from_analysis_package("modules.packages.vawtrak")
        pkg_class()

    def test_vbejse(self):
        pkg_class = self.class_from_analysis_package("modules.packages.vbejse")
        pkg_class()

    def test_vbs(self):
        pkg_class = self.class_from_analysis_package("modules.packages.vbs")
        pkg_class()

    def test_wsf(self):
        pkg_class = self.class_from_analysis_package("modules.packages.wsf")
        pkg_class()

    def test_xls(self):
        pkg_class = self.class_from_analysis_package("modules.packages.xls")
        pkg_class()

    def test_xls2016(self):
        pkg_class = self.class_from_analysis_package("modules.packages.xls2016")
        pkg_class()

    def test_xps(self):
        pkg_class = self.class_from_analysis_package("modules.packages.xps")
        pkg_class()

    def test_xslt(self):
        pkg_class = self.class_from_analysis_package("modules.packages.xslt")
        pkg_class()

    def test_zip(self):
        pkg_class = self.class_from_analysis_package("modules.packages.zip")
        pkg_class()

    def test_zip_compound(self):
        pkg_class = self.class_from_analysis_package("modules.packages.zip_compound")
        pkg_class()
