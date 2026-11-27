import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

if sys.platform == "linux":
    import analyzer
    from analyzer import DUMPED_LIST, PROCESS_LIST, SEEN_LIST


class _StopLoopError(Exception):
    pass


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux")
class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        PROCESS_LIST.clear()
        SEEN_LIST.clear()
        DUMPED_LIST.clear()

    def tearDown(self):
        PROCESS_LIST.clear()
        SEEN_LIST.clear()
        DUMPED_LIST.clear()

    def test_add_pids(self):
        """Test add_pids with a variety of valid types"""
        # Check that both sets are empty
        self.assertEqual(PROCESS_LIST, set())
        self.assertEqual(SEEN_LIST, set())

        pids = [123, 456, 789]
        # Add a list of PIDs
        analyzer.add_pids([str(pids[0]), pids[1]])
        # Add a set of PIDs
        analyzer.add_pids(set([pids[0], pids[2]]))
        # Add a tuple of PIDs
        analyzer.add_pids((pids[1], pids[2]))

        self.assertEqual(PROCESS_LIST, set(pids))
        self.assertEqual(SEEN_LIST, set(pids))

    def test_add_pids_invalid_var(self):
        """Test add_pids with an invalid type"""
        with self.assertRaises(TypeError):
            analyzer.add_pids(analyzer.add_pids)

    def test_is_procdump_enabled(self):
        """Test option parsing for child process memory dumping."""
        self.assertTrue(analyzer._is_procdump_enabled(None))
        self.assertTrue(analyzer._is_procdump_enabled({}))
        self.assertTrue(analyzer._is_procdump_enabled(0.25))
        self.assertTrue(analyzer._is_procdump_enabled({"procdump": "1"}))
        self.assertTrue(analyzer._is_procdump_enabled({"procdump": "true"}))
        self.assertTrue(analyzer._is_procdump_enabled({"procmemdump": "1"}))

        for disabled in ("0", "false", "no", "off", " FALSE ", 0, False):
            self.assertFalse(analyzer._is_procdump_enabled({"procdump": disabled}))
            self.assertFalse(analyzer._is_procdump_enabled({"procmemdump": disabled}))

    def test_monitor_new_processes_defaults_and_positional_interval(self):
        """monitor_new_processes dumps new child PIDs by default and preserves positional interval."""
        with (
            patch.object(analyzer, "get_all_child_processes", side_effect=[[101], [101, 202]]),
            patch.object(analyzer, "dump_memory") as mock_dump,
            patch.object(analyzer.time, "sleep", side_effect=_StopLoopError) as mock_sleep,
        ):
            with self.assertRaises(_StopLoopError):
                analyzer.monitor_new_processes(100, 0.05)

        mock_sleep.assert_called_once_with(0.05)
        mock_dump.assert_called_once_with(202)
        self.assertEqual(PROCESS_LIST, {202})

    def test_monitor_new_processes_disabled_skips_dump_but_tracks_pids(self):
        """Disabling procdump/procmemdump skips dump_memory while still adding child PIDs."""
        for opts in (
            {"procdump": "0"},
            {"procdump": "false"},
            {"procdump": "no"},
            {"procdump": "off"},
            {"procmemdump": "0"},
        ):
            PROCESS_LIST.clear()
            SEEN_LIST.clear()
            with (
                patch.object(analyzer, "get_all_child_processes", side_effect=[[], [303]]),
                patch.object(analyzer, "dump_memory") as mock_dump,
                patch.object(analyzer.time, "sleep", side_effect=_StopLoopError),
            ):
                with self.assertRaises(_StopLoopError):
                    analyzer.monitor_new_processes(100, options=opts)

            mock_dump.assert_not_called()
            self.assertEqual(PROCESS_LIST, {303})

    def test_analyzer_run_passes_options_to_monitor_thread(self):
        """Analyzer.run forwards self.options via kwargs to monitor_new_processes."""
        inst = analyzer.Analyzer()
        fake_pkg = MagicMock()
        fake_pkg.start.return_value = 4242
        fake_pkg.check.return_value = False
        fake_pkg.package_files.return_value = None

        def fake_prepare():
            inst.target = "/tmp/sample.elf"
            inst.options = {"procdump": "0"}
            inst.config = SimpleNamespace(
                category="file",
                package="generic",
                file_type="ELF 64-bit LSB executable",
                file_name="sample.elf",
                options="procdump=0",
                enforce_timeout=False,
                timeout="5",
                id=1,
                terminate_processes=False,
            )

        with (
            patch.object(inst, "prepare", side_effect=fake_prepare),
            patch.object(inst, "complete", return_value=True),
            patch.object(analyzer.pkgutil, "iter_modules", return_value=[]),
            patch.object(analyzer.Auxiliary, "__subclasses__", return_value=[]),
            patch.object(analyzer, "choose_package_class", return_value=lambda *_a, **_kw: fake_pkg),
            patch.object(analyzer, "Process") as mock_proc,
            patch.object(analyzer, "Thread") as mock_thread,
            patch.object(analyzer.time, "sleep"),
        ):
            mock_proc.return_value.is_alive.return_value = True
            self.assertTrue(inst.run())

        mock_thread.assert_called_once_with(
            target=analyzer.monitor_new_processes,
            args=(4242,),
            kwargs={"options": {"procdump": "0"}},
            daemon=True,
        )
        mock_thread.return_value.start.assert_called_once_with()

    def test_analyzer_run_handles_empty_and_multi_pids_and_preserves_internal_typeerror(self):
        """Empty PID list finishes cleanly; multi-PID monitors all roots; internal TypeError is not masked."""

        def _make_config():
            return SimpleNamespace(
                category="file",
                package="generic",
                file_type="archive",
                file_name="bundle.zip",
                options="",
                enforce_timeout=False,
                timeout="5",
                id=1,
                terminate_processes=False,
            )

        # 1. Empty PID list must not raise ValueError and must still call pack.finish().
        inst_empty = analyzer.Analyzer()
        empty_pkg = MagicMock()
        empty_pkg.start.return_value = []
        empty_pkg.check.return_value = False
        empty_pkg.package_files.return_value = None

        def prep_empty():
            inst_empty.target = "/tmp/bundle.zip"
            inst_empty.options = {}
            inst_empty.config = _make_config()

        with (
            patch.object(inst_empty, "prepare", side_effect=prep_empty),
            patch.object(inst_empty, "complete", return_value=True),
            patch.object(analyzer.pkgutil, "iter_modules", return_value=[]),
            patch.object(analyzer.Auxiliary, "__subclasses__", return_value=[]),
            patch.object(analyzer, "choose_package_class", return_value=lambda *_a, **_kw: empty_pkg),
            patch.object(analyzer, "Thread") as mock_thread,
            patch.object(analyzer.time, "sleep"),
        ):
            self.assertTrue(inst_empty.run())
        mock_thread.assert_not_called()
        empty_pkg.finish.assert_called_once_with()

        # 2. Multi-PID package passes all sorted PIDs to monitor_new_processes.
        PROCESS_LIST.clear()
        SEEN_LIST.clear()
        inst_multi = analyzer.Analyzer()
        multi_pkg = MagicMock()
        multi_pkg.start.return_value = [2002, 1001]
        multi_pkg.check.return_value = False
        multi_pkg.package_files.return_value = None

        def prep_multi():
            inst_multi.target = "/tmp/bundle.zip"
            inst_multi.options = {}
            inst_multi.config = _make_config()

        with (
            patch.object(inst_multi, "prepare", side_effect=prep_multi),
            patch.object(inst_multi, "complete", return_value=True),
            patch.object(analyzer.pkgutil, "iter_modules", return_value=[]),
            patch.object(analyzer.Auxiliary, "__subclasses__", return_value=[]),
            patch.object(analyzer, "choose_package_class", return_value=lambda *_a, **_kw: multi_pkg),
            patch.object(analyzer, "Process") as mock_proc,
            patch.object(analyzer, "Thread") as mock_thread,
            patch.object(analyzer.time, "sleep"),
        ):
            mock_proc.return_value.is_alive.return_value = True
            self.assertTrue(inst_multi.run())
        mock_thread.assert_called_once_with(
            target=analyzer.monitor_new_processes,
            args=((1001, 2002),),
            kwargs={"options": {}},
            daemon=True,
        )

        # 3. Internal TypeError inside start(path) must NOT retry start() with 0 args.
        PROCESS_LIST.clear()
        SEEN_LIST.clear()
        calls = []

        class BrokenPkg:
            def start(self, path):
                calls.append(path)
                raise TypeError("internal bug inside start")

        inst_err = analyzer.Analyzer()

        def prep_err():
            inst_err.target = "/tmp/bundle.zip"
            inst_err.options = {}
            inst_err.config = _make_config()

        with (
            patch.object(inst_err, "prepare", side_effect=prep_err),
            patch.object(analyzer.pkgutil, "iter_modules", return_value=[]),
            patch.object(analyzer.Auxiliary, "__subclasses__", return_value=[]),
            patch.object(analyzer, "choose_package_class", return_value=lambda *_a, **_kw: BrokenPkg()),
        ):
            with self.assertRaisesRegex(analyzer.CuckooError, "internal bug inside start"):
                inst_err.run()
        self.assertEqual(calls, ["/tmp/bundle.zip"])

    def test_all_auxiliary_modules_import_cleanly(self):
        """Importing all Linux auxiliary modules must not crash when optional deps are absent."""
        import importlib
        import pkgutil
        from modules import auxiliary

        prefix = f"{auxiliary.__name__}."
        imported = []
        for _loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
            if ispkg:
                continue
            importlib.import_module(name)
            imported.append(name)

        self.assertIn("modules.auxiliary.filecollector", imported)
        self.assertIn("modules.auxiliary.human", imported)
        self.assertIn("modules.auxiliary.screenshots", imported)

    def test_screenshot_pillow_major_version_check(self):
        """Double-digit Pillow versions (e.g. 12.x) must not trigger the <5 upgrade warning."""
        import importlib
        import sys
        import types

        fake_pil = types.ModuleType("PIL")
        fake_pil.__version__ = "12.3.0"
        fake_pil.ImageDraw = types.ModuleType("PIL.ImageDraw")
        fake_chops = types.ModuleType("PIL.ImageChops")
        fake_chops.difference = lambda a, b: None

        try:
            with patch.dict(sys.modules, {"PIL": fake_pil, "PIL.ImageChops": fake_chops, "PIL.ImageDraw": fake_pil.ImageDraw}):
                import lib.api.screenshot as screenshot_mod

                with self.assertNoLogs("lib.api.screenshot", level="INFO"):
                    importlib.reload(screenshot_mod)
                self.assertTrue(screenshot_mod.HAVE_PIL)

                fake_pil.__version__ = "4.3.0"
                with self.assertLogs("lib.api.screenshot", level="INFO") as logs:
                    importlib.reload(screenshot_mod)
                self.assertTrue(any("upgrade Pillow" in msg for msg in logs.output))
        finally:
            sys.modules.pop("lib.api.screenshot", None)

