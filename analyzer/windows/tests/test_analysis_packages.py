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
        cls = pkg_classes[0]
        self.assertTrue(issubclass(cls, Package))
        return cls

    def test_has_summary_description(self):
        """Ensure each Package class in modules.packages has a summary and description."""
        clazz = Package
        module = importlib.import_module("modules.packages")
        subclasses = [
            cls
            for _, mod in inspect.getmembers(module)
            if inspect.ismodule(mod)
            for name, cls in inspect.getmembers(mod)
            if inspect.isclass(cls) and issubclass(cls, clazz) and cls != clazz
        ]
        self.assertGreater(len(subclasses), 0)
        for subclass in subclasses:
            self.assertTrue(hasattr(subclass, "summary"))
            self.assertTrue(hasattr(subclass, "description"))
            self.assertGreater(len(subclass.summary), 0)
            self.assertGreater(len(subclass.description), 0)

    def test_choose_package_Shellcode_Unpacker(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Shellcode-Unpacker")
        pkg_class()

    def test_Shellcode(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Shellcode")
        obj = pkg_class()
        self.assertEqual("offset", obj.option_names[0])
        expected_summary = "Execute 32-bit Shellcode using loader.exe."
        self.assertEqual(expected_summary, obj.summary)

    def test_Shellcode_x64(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Shellcode_x64")
        pkg_class()

    def test_Unpacker(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker")
        obj = pkg_class()
        expected_summary = """Execute a .exe file with the unpacker option."""
        self.assertEqual(expected_summary, obj.summary)

    def test_Unpacker_dll(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker_dll")
        obj = pkg_class()
        self.assertEqual("arguments", obj.option_names[0])
        self.assertEqual("dllloader", obj.option_names[1])
        self.assertEqual("function", obj.option_names[2])

    def test_Unpacker_js(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker_js")
        obj = pkg_class()
        expected_summary = """Execute a .JS file using wscript.exe."""
        self.assertEqual(expected_summary, obj.summary)

    def test_Unpacker_ps1(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker_ps1")
        obj = pkg_class()
        expected_summary = """Execute a sample file with powershell."""
        self.assertEqual(expected_summary, obj.summary)

    def test_Unpacker_regsvr(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker_regsvr")
        pkg_class()

    def test_Unpacker_zip(self):
        pkg_class = self.class_from_analysis_package("modules.packages.Unpacker_zip")
        obj = pkg_class()
        expected_summary = """Unzip a file with the supplied password, execute its contents."""
        self.assertEqual(expected_summary, obj.summary)

    def test_access(self):
        pkg_class = self.class_from_analysis_package("modules.packages.access")
        pkg_class()

    def test_applet(self):
        pkg_class = self.class_from_analysis_package("modules.packages.applet")
        obj = pkg_class()
        self.assertEqual("class", obj.option_names[0])
        summary = """Open a java applet using firefox (or iexplore)."""
        self.assertEqual(summary, obj.summary)

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
        obj = pkg_class()
        self.assertEqual("Run the supplied executable.", obj.summary)

    def test_firefox(self):
        pkg_class = self.class_from_analysis_package("modules.packages.firefox")
        obj = pkg_class()
        self.assertEqual("Open the URL in firefox.", obj.summary)

    def test_generic(self):
        pkg_class = self.class_from_analysis_package("modules.packages.generic")
        obj = pkg_class()
        self.assertEqual("Execute the sample file with cmd.exe.", obj.summary)

    def test_hta(self):
        pkg_class = self.class_from_analysis_package("modules.packages.hta")
        expected_summary = "Execute the sample with mshta.exe."
        obj = pkg_class()
        self.assertEqual(expected_summary, obj.summary)

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
        expected_summary = "Execute a java class using java.exe."
        obj = pkg_class()
        self.assertEqual(expected_summary, obj.summary)
        self.assertEqual("class", obj.option_names[0])

    def test_js(self):
        pkg_class = self.class_from_analysis_package("modules.packages.js")
        pkg_class()

    def test_js_antivm(self):
        pkg_class = self.class_from_analysis_package("modules.packages.js_antivm")
        pkg_class()

    def test_lnk(self):
        pkg_class = self.class_from_analysis_package("modules.packages.lnk")
        obj = pkg_class()
        self.assertEqual("Execute a .lnk file using cmd.exe.", obj.summary)

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
        obj = pkg_class()
        expected_summary = "Execute a sample with msiexec.exe."
        self.assertEqual(expected_summary, obj.summary)

    def test_msix(self):
        pkg_class = self.class_from_analysis_package("modules.packages.msix")
        obj = pkg_class()
        expected_summary = "Execute a sample .msix file with powershell."
        self.assertEqual(expected_summary, obj.summary)

    def test_nsis(self):
        pkg_class = self.class_from_analysis_package("modules.packages.nsis")
        pkg_class()

    def test_ollydbg(self):
        pkg_class = self.class_from_analysis_package("modules.packages.ollydbg")
        pkg_class()

    def test_one(self):
        pkg_class = self.class_from_analysis_package("modules.packages.one")
        obj = pkg_class()
        expected_summary = "Open a sample file with ONENOTE.EXE."
        self.assertEqual(expected_summary, obj.summary)

    def test_pdf(self):
        pkg_class = self.class_from_analysis_package("modules.packages.pdf")
        obj = pkg_class()
        expected_summary = "Open .pdf file with Adobe Reader / Acrobat."
        self.assertEqual(expected_summary, obj.summary)

    def test_ppt(self):
        pkg_class = self.class_from_analysis_package("modules.packages.ppt")
        obj = pkg_class()
        expected_summary = "Open sample file with Powerpoint."
        self.assertEqual(expected_summary, obj.summary)

    def test_ppt2016(self):
        pkg_class = self.class_from_analysis_package("modules.packages.ppt2016")
        pkg_class()

    def test_ps1(self):
        pkg_class = self.class_from_analysis_package("modules.packages.ps1")
        expected_summary = "Execute a sample file with powershell."
        obj = pkg_class()
        self.assertEqual(expected_summary, obj.summary)
        self.assertEqual("pwsh", obj.option_names[0])

    def test_pub(self):
        pkg_class = self.class_from_analysis_package("modules.packages.pub")
        expected_summary = "Open a .pub file with MS Publisher."
        obj = pkg_class()
        self.assertEqual(expected_summary, obj.summary)

    def test_pub2016(self):
        pkg_class = self.class_from_analysis_package("modules.packages.pub2016")
        expected_summary = "Open a .pub file with MS Publisher."
        obj = pkg_class()
        self.assertEqual(expected_summary, obj.summary)

    def test_python(self):
        pkg_class = self.class_from_analysis_package("modules.packages.python")
        expected_summary = "Execute sample file with python."
        obj = pkg_class()
        self.assertEqual(expected_summary, obj.summary)

    def test_rar(self):
        pkg_class = self.class_from_analysis_package("modules.packages.rar")
        expected_summary = "Unpack a .rar archive with the given password and execute the contents appropriately."
        obj = pkg_class()
        self.assertEqual(expected_summary, obj.summary)

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
