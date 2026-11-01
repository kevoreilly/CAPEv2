import unittest
from unittest.mock import Mock, mock_open, patch

from modules.packages.apk import Apk


def make_pkg(target="/data/local/tmp/sample.apk", options=None, timeout=60):
    return Apk(target, options=options or {}, timeout=timeout)


class TestApkInstall(unittest.TestCase):
    @patch("modules.packages.apk.subprocess.check_output")
    @patch("modules.packages.apk.subprocess.run")
    def test_install_single_new_package(self, mock_run, mock_check_output):
        mock_run.return_value = Mock(stdout=b"Success\n")
        mock_check_output.side_effect = [
            b"package:com.existing.app\n",
            b"package:com.existing.app\npackage:com.new.app\n",
        ]
        pkg = make_pkg()
        self.assertEqual(pkg._install(), "com.new.app")

    @patch("modules.packages.apk.subprocess.run")
    def test_install_pm_failure_raises(self, mock_run):
        mock_run.return_value = Mock(stdout=b"Failure [INSTALL_FAILED_INVALID_APK]\n")
        pkg = make_pkg()
        with self.assertRaises(Exception):
            pkg._install()

    @patch.object(Apk, "_package_name_from_aapt", return_value="com.aapt.resolved")
    @patch("modules.packages.apk.subprocess.check_output")
    @patch("modules.packages.apk.subprocess.run")
    def test_install_reinstall_falls_back_to_aapt(self, mock_run, mock_check_output, mock_aapt):
        # Same package list before and after: pm list packages never shows
        # a reinstall of an already-present app as "new".
        mock_run.return_value = Mock(stdout=b"Success\n")
        mock_check_output.return_value = b"package:com.existing.app\n"
        pkg = make_pkg()
        self.assertEqual(pkg._install(), "com.aapt.resolved")
        mock_aapt.assert_called_once()

    @patch.object(Apk, "_package_name_from_aapt", return_value=None)
    @patch("modules.packages.apk.subprocess.check_output")
    @patch("modules.packages.apk.subprocess.run")
    def test_install_multiple_new_packages_picks_one_and_warns(self, mock_run, mock_check_output, mock_aapt):
        mock_run.return_value = Mock(stdout=b"Success\n")
        mock_check_output.side_effect = [
            b"package:com.existing.app\n",
            b"package:com.existing.app\npackage:com.new.one\npackage:com.new.two\n",
        ]
        pkg = make_pkg()
        result = pkg._install()
        self.assertIn(result, {"com.new.one", "com.new.two"})

    @patch.object(Apk, "_package_name_from_aapt", return_value=None)
    @patch("modules.packages.apk.subprocess.check_output")
    @patch("modules.packages.apk.subprocess.run")
    def test_install_no_new_packages_and_no_aapt_raises(self, mock_run, mock_check_output, mock_aapt):
        mock_run.return_value = Mock(stdout=b"Success\n")
        mock_check_output.return_value = b"package:com.existing.app\n"
        pkg = make_pkg()
        with self.assertRaises(Exception):
            pkg._install()


class TestApkLaunch(unittest.TestCase):
    @patch("modules.packages.apk.subprocess.run")
    def test_launch_argv_uses_positional_parameter_substitution(self, mock_run):
        """The script body passed to `sh -c` must be a fixed literal with no
        string-interpolation of package_name -- it must only ever reach the
        shell as $1, so a malicious package name can't alter shell syntax.
        """
        pkg = make_pkg()
        pkg.package_name = "com.evil.app; rm -rf /"
        pkg._launch()
        argv = mock_run.call_args[0][0]
        self.assertEqual(argv[0], "sh")
        self.assertEqual(argv[1], "-c")
        self.assertNotIn(pkg.package_name, argv[2])
        self.assertEqual(argv[3], "sh")
        self.assertEqual(argv[4], pkg.package_name)


class TestApkPidDiscovery(unittest.TestCase):
    def test_start_raises_when_pid_never_found(self):
        pkg = make_pkg()
        with patch.object(pkg, "_install", return_value="com.test.app"), patch.object(
            pkg, "_launch"
        ), patch.object(pkg, "_wait_for_pid", return_value=None):
            with self.assertRaises(Exception):
                pkg.start()

    @patch("modules.packages.apk.subprocess.check_output")
    def test_pid_for_package_via_pidof(self, mock_check_output):
        mock_check_output.return_value = b"1234\n"
        pkg = make_pkg()
        pkg.package_name = "com.test.app"
        self.assertEqual(pkg._pid_for_package(), 1234)

    @patch("modules.packages.apk.os.listdir", return_value=["1234"])
    @patch("modules.packages.apk.subprocess.check_output", side_effect=FileNotFoundError)
    def test_pid_for_package_falls_back_to_proc_scan(self, mock_check_output, mock_listdir):
        pkg = make_pkg()
        pkg.package_name = "com.test.app"
        with patch("builtins.open", mock_open(read_data=b"com.test.app\x00")):
            self.assertEqual(pkg._pid_for_package(), 1234)


class TestApkFinish(unittest.TestCase):
    @patch("modules.packages.apk.subprocess.run")
    def test_finish_force_stops_installed_package(self, mock_run):
        pkg = make_pkg()
        pkg.package_name = "com.test.app"
        pkg.finish()
        mock_run.assert_called_once()
        self.assertEqual(mock_run.call_args[0][0], ["am", "force-stop", "com.test.app"])

    @patch("modules.packages.apk.subprocess.run")
    def test_finish_noop_when_no_package_installed(self, mock_run):
        pkg = make_pkg()
        pkg.finish()
        mock_run.assert_not_called()
