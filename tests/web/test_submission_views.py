import ast
import os
import re
import textwrap

import pytest
from django.test import SimpleTestCase
from submission.views import (
    correlate_platform_packages,
    get_form_data,
    get_lib_common_constants,
    get_package_info,
    parse_ast,
    web_conf,
)


@pytest.mark.usefixtures("db")
class TestSubmissionViews(SimpleTestCase):
    maxDiff = None

    def setUp(self):
        self.linux_enabled = web_conf.linux.enabled
        self.excluded_packages = web_conf.package_exclusion.packages
        self.linux_package_dir = os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "..", "..", "analyzer", "linux", "modules", "packages"
        )
        self.windows_package_dir = os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "..", "..", "analyzer", "windows", "modules", "packages"
        )
        web_conf.linux.enabled = True

    def tearDown(self):
        web_conf.linux.enabled = self.linux_enabled
        web_conf.package_exclusion.packages = self.excluded_packages

    def find_in_list(self, regex, list_of_strings):
        """Test if the regex matches any string in the list."""
        pattern = re.compile(regex, flags=re.DOTALL)
        for string in list_of_strings:
            if pattern.match(string):
                return True
        return False

    def one_should_match(self, regex, list_of_strings):
        """One of the strings should match."""
        found = self.find_in_list(regex, list_of_strings)
        self.assertTrue(found, f"No string matched <{regex}>")

    def none_should_match(self, regex, list_of_strings):
        """None of the strings should match."""
        found = self.find_in_list(regex, list_of_strings)
        self.assertFalse(found, f"One or more strings matched <{regex}>")

    def test_submission_page(self):
        """The submission page should have a package selection form.

        The form should have a list of at least 10 options.
        """
        submission_page = self.client.get("/submit/#file")
        self.assertIsNotNone(submission_page.content)
        self.assertIn("Analysis Package", submission_page.content.decode())
        pattern = re.compile(r'select class="form-control" id="form_package" name="package">(.*?)</select>', flags=re.DOTALL)
        matches = re.findall(pattern, submission_page.content.decode())
        self.assertEqual(len(matches), 1)
        group0 = matches[0].strip()
        self.assertTrue(group0.startswith("<option value"))
        self.assertTrue(group0.endswith("</option>"))
        option_pattern = re.compile(r"<option (.*?)</option>", flags=re.DOTALL)
        options = re.findall(option_pattern, group0)
        self.assertEqual('value="" title="">Detect Automatically', options[0])

        self.one_should_match('value="exe" title=".*">exe - .*', options)
        self.one_should_match('value="Unpacker" title="[^"]*">Unpacker', options)
        self.one_should_match(".*ichitaro.*", options)
        self.one_should_match(".*chromium.*", options)
        self.assertGreater(len(options), 10)
        for opt in options:
            self.assertTrue(opt.startswith("value="))

    def test_package_exclusion(self):
        """Pick a couple of packages to exclude, to test exclusion"""
        web_conf.package_exclusion.packages = "chromium,chromium_ext,ichitaro,Shellcode"
        submission_page = self.client.get("/submit/#file")
        self.assertIsNotNone(submission_page.content)
        self.assertIn("Analysis Package", submission_page.content.decode())
        option_pattern = re.compile(r"<option (.*?)</option>", flags=re.DOTALL)
        options = re.findall(option_pattern, submission_page.content.decode())
        self.assertGreater(len(options), 10)
        # excluded packages should not be listed
        self.none_should_match(".*ichitaro.*", options)
        self.none_should_match(".*chromium.*", options)
        # Package 'Shellcode' was excluded, but not 'Shellcode-Unpacker'.
        self.none_should_match('.*"Shellcode".*', options)
        self.one_should_match('.*"Shellcode-Unpacker".*', options)

    def test_get_package_exe_info(self):
        """Get the package info from exe.py."""
        expected_options = ("str1", "str2", "str3")
        context = {
            "OPT_ARGUMENTS": expected_options[0],
            "OPT_APPDATA": expected_options[1],
            "OPT_RUNASX86": expected_options[2],
            "ARCHIVE_OPTIONS": (1, 2),
            "DLL_OPTIONS": (3, 4),
        }
        actual = get_package_info(self.windows_package_dir, "exe.py", "windows", context)
        self.assertEqual("exe", actual["name"])
        self.assertEqual("Exe", actual["classname"])
        self.assertIn("summary", actual)
        self.assertIn("description", actual)
        self.assertEqual("Runs the supplied executable.", actual["summary"])
        expected_description = textwrap.dedent(
            f"""\
        Executes the given sample, passing '{context["OPT_ARGUMENTS"]}' if specified.
        Use the '{context["OPT_APPDATA"]}' option to run the executable from the APPDATA directory.
        Use the '{context["OPT_RUNASX86"]}' option to set the 32BITREQUIRED flag in the PE header,
        using 'CorFlags.exe /32bit+'.
        The .exe extension will be added automatically.
        OPTIONS: {expected_options}"""
        )
        actual_description = actual["description"]
        self.assertEqual(expected_description, actual_description)
        self.assertEqual(expected_options, actual["option_names"])

    def test_get_package_rar_info(self):
        """Get the package info from rar.py."""
        context = {
            "ARCHIVE_OPTIONS": (2, 5, 1, 3),
            "DLL_OPTIONS": (3, 4, 2, 5),
        }
        actual = get_package_info(self.windows_package_dir, "rar.py", "windows", context)
        self.assertIn("name", actual)
        self.assertEqual("rar", actual["name"])
        self.assertIn("summary", actual)
        self.assertIn("description", actual)
        self.assertIn("option_names", actual)
        self.assertEqual([1, 2, 3, 4, 5], actual["option_names"])

    def test_get_package_one(self):
        """Get the package info from one.py."""
        context = dict()
        actual = get_package_info(self.windows_package_dir, "one.py", "windows", context)
        self.assertEqual("one", actual["name"])
        self.assertNotIn("_OPT_YARASCAN", actual["description"])
        self.assertIn("'yarascan'", actual["description"])

    def test_get_package_bash(self):
        """Get the package info from bash.py."""
        context = {
            "summary": "should not be preserved",
            "description": "should not be preserved",
            "option_names": ("opt1", "opt2", "opt3"),
        }
        actual = get_package_info(self.linux_package_dir, "bash.py", "linux", context)
        self.assertEqual("bash", actual["name"])
        self.assertEqual("linux", actual["platform"])
        self.assertNotEqual("should not be preserved", actual["summary"])
        self.assertNotEqual("should not be preserved", actual["description"])
        # The bash package does not have a summary, description, or option_names.
        self.assertIn(" has no summary", actual["summary"])
        self.assertIn(" has no description", actual["description"])
        self.assertFalse(actual["option_names"])

    def test_get_form_data(self):
        """Use get_form_data() and check the values returned."""
        packages, machines = get_form_data()
        self.assertIsInstance(packages, list)
        self.assertIsInstance(machines, list)
        self.assertGreater(len(packages), 10)
        self.assertGreater(len(machines), 0)
        platforms = {package["platform"] for package in packages}
        self.assertIn("windows", platforms)
        self.assertIn("linux", platforms)
        package_names = {package["name"] for package in packages}
        self.assertIn("bash (linux only)", package_names)

    def test_get_lib_common_constants(self):
        """Ensure we get the constants from lib/common/constants.py"""
        actual = get_lib_common_constants(platform="windows")
        self.assertIsInstance(actual, dict)
        self.assertEqual("runasx86", actual["OPT_RUNASX86"])
        self.assertCountEqual(("file", "password"), actual["ARCHIVE_OPTIONS"])
        self.assertCountEqual(("arguments", "dllloader", "function"), actual["DLL_OPTIONS"])
        self.assertIn("SystemDrive", actual["TRUSTED_PATH_TEXT"])
        self.assertIn("SystemDrive", actual["MSOFFICE_TRUSTED_PATH"])

    def test_parse_ast(self):
        """Test some of the parse_ast functionality."""
        var1 = "x"
        val1 = "value-of-x"

        # Test ast.BinOp
        code1 = f"{var1} = 'value-of-' + 'x'"
        tree = ast.parse(code1)
        actual = parse_ast(tree.body)
        self.assertEqual(val1, actual[var1])

        # Test ast.Name lookup from context
        var2 = "y"
        code2 = f"{var1} = '{val1}'\n{var2} = f'{{x}}'"
        tree = ast.parse(code2)
        actual = parse_ast(tree.body)
        self.assertEqual(val1, actual[var1])
        self.assertEqual(val1, actual[var2])

        # Test ast.Tuple handling.
        code3 = f"{var1} = (1, 2)"
        tree = ast.parse(code3)
        actual = parse_ast(tree.body)
        self.assertEqual((1, 2), actual[var1])

    def test_correlate_platform_packages(self):
        """Test the correlate_platform_packages function."""
        win_packages = [
            {
                "name": "firefox",
                "summary": "opens a url with firefox",
                "platform": "windows",
            },
            {
                "name": "autoit",
                "summary": "opens a file with autoit",
                "platform": "windows",
            },
        ]
        linux_packages = [
            {
                "name": "firefox",
                "platform": "linux",
            },
            {
                "name": "bash",
                "platform": "linux",
            },
        ]
        package_dict = {
            "windows": win_packages,
            "linux": linux_packages,
        }
        actual = correlate_platform_packages(package_dict)
        self.assertEqual(3, len(actual))
        names = [item["name"] for item in actual]
        self.assertIn("firefox", names)
        self.assertIn("bash (linux only)", names)
