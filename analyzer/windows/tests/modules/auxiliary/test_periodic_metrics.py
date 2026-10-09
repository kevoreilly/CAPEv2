import json
import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from modules.auxiliary import periodic_metrics as metrics
from lib.core.config import Config


class TestPeriodicMetrics(unittest.TestCase):
    def collector(self, enabled=True, options=None, interval=1):
        return metrics.PeriodicMetrics(options or {}, SimpleNamespace(periodic_metrics=enabled, periodic_metrics_interval=interval))

    def provider(self):
        provider = Mock()
        provider.system_times.return_value = (100, 200, 100)
        provider.memory.return_value = {"memory_load_percent": 50, "total_physical_bytes": 1000, "available_physical_bytes": 500}
        provider.process.return_value = {"creation_time_100ns": 123, "cpu_time_100ns": 10, "working_set_bytes": 256}
        return provider

    def test_disabled_does_not_create_provider_or_file(self):
        collector = self.collector(enabled=False)
        with patch.object(metrics, "WindowsMetrics") as provider:
            collector.run()
            collector.finish()
        provider.assert_not_called()
        self.assertIsNone(collector._path)

    def test_old_config_defaults_to_disabled(self):
        self.assertFalse(metrics.PeriodicMetrics({}, SimpleNamespace()).enabled)

    def test_interval_option_overrides_config(self):
        self.assertEqual(self.collector(options={"periodic_metrics_interval": "0.5"}, interval=2).interval, 0.5)

    def test_guest_analysis_config_accepts_fractional_interval(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "analysis.conf")
            with open(path, "w", encoding="utf-8") as config_file:
                config_file.write("[analysis]\nperiodic_metrics = yes\nperiodic_metrics_interval = 0.5\n")
            collector = metrics.PeriodicMetrics({}, Config(path))
        self.assertTrue(collector.enabled)
        self.assertEqual(collector.interval, 0.5)

    def test_invalid_intervals_fall_back(self):
        for interval in ("invalid", 0, -1, 0.09, 61, "nan", "inf", None):
            with self.subTest(interval=interval):
                self.assertEqual(self.collector(interval=interval).interval, 1)

    def test_cpu_deltas_and_timestamps(self):
        collector = self.collector()
        provider = self.provider()
        collector.add_pid(42)
        collector.add_pid(42)
        with patch.object(
            metrics.time, "perf_counter_ns", side_effect=[1_000_000_000, 1_000_000_000, 3_000_000_000, 3_000_000_000]
        ):
            first = collector.sample(provider, 1_000_000_000)
            provider.system_times.return_value = (150, 300, 200)
            provider.process.return_value = {"creation_time_100ns": 123, "cpu_time_100ns": 10_000_010}
            second = collector.sample(provider, 1_000_000_000)
        self.assertIsNone(first["system"]["cpu_percent"])
        self.assertIsNone(first["processes"][0]["cpu_percent"])
        self.assertEqual(len(first["processes"]), 1)
        self.assertEqual(second["system"]["cpu_percent"], 75)
        self.assertEqual(second["processes"][0]["cpu_percent"], 50)
        self.assertEqual(second["elapsed_seconds"], 2)
        self.assertTrue(second["timestamp_utc"].endswith("+00:00"))
        self.assertEqual(second["system"]["memory_load_percent"], 50)

    def test_reused_pid_has_no_cpu_delta(self):
        collector = self.collector()
        provider = self.provider()
        collector.add_pid(42)
        collector.sample(provider, 0)
        provider.process.return_value = {"creation_time_100ns": 456, "cpu_time_100ns": 100_000}
        self.assertIsNone(collector.sample(provider, 0)["processes"][0]["cpu_percent"])

    def test_failures_are_recorded_and_reset_cpu_baselines(self):
        collector = self.collector()
        provider = self.provider()
        collector.add_pid(42)
        collector.sample(provider, 0)
        provider.system_times.side_effect = OSError("system unavailable")
        provider.memory.side_effect = OSError("memory unavailable")
        provider.process.side_effect = OSError("process exited or access denied")
        row = collector.sample(provider, 0)
        self.assertIsNone(row["system"]["cpu_percent"])
        self.assertEqual(len(row["errors"]), 2)
        self.assertIn("error", row["processes"][0])
        provider.system_times.side_effect = None
        provider.memory.side_effect = None
        provider.process.side_effect = None
        recovered = collector.sample(provider, 0)
        self.assertIsNone(recovered["system"]["cpu_percent"])
        self.assertIsNone(recovered["processes"][0]["cpu_percent"])

    def test_deleted_pid_baseline_is_discarded(self):
        collector = self.collector()
        provider = self.provider()
        collector.add_pid(42)
        collector.sample(provider, 0)
        collector.del_pid(42)
        self.assertEqual(collector.sample(provider, 0)["processes"], [])
        self.assertEqual(collector._previous_processes, {})

    def test_invalid_or_zero_system_delta_is_unknown(self):
        for next_times in ((100, 200, 100), (99, 201, 101), (110, 201, 101)):
            collector = self.collector()
            provider = self.provider()
            collector.sample(provider, 0)
            provider.system_times.return_value = next_times
            self.assertIsNone(collector.sample(provider, 0)["system"]["cpu_percent"])

    def test_immediate_sampling_upload_and_cleanup(self):
        collector = self.collector(interval=60)
        provider = self.provider()
        with patch.object(metrics, "WindowsMetrics", return_value=provider), patch.object(metrics, "upload_to_host") as upload:
            # Stop during the first wait: sampling must happen before waiting a full interval.
            with patch.object(collector._stopped, "wait", side_effect=lambda delay: collector.stop()):
                collector.run()
            path = collector._path
            try:
                with open(path, encoding="utf-8") as output:
                    rows = [json.loads(line) for line in output]
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["schema_version"], 1)
                collector.finish()
                collector.finish()
                upload.assert_called_once_with(path, metrics.UPLOAD_PATH)
                self.assertFalse(os.path.exists(path))
            finally:
                if os.path.exists(path):
                    os.unlink(path)

    def test_slow_sample_skips_missed_slots(self):
        collector = self.collector()
        with (
            patch.object(metrics, "WindowsMetrics", return_value=self.provider()),
            patch.object(metrics.time, "perf_counter", side_effect=[0, 3.5, 3.5]),
            patch.object(collector._stopped, "wait", side_effect=lambda delay: collector.stop()) as wait,
        ):
            collector.run()
        try:
            wait.assert_called_once_with(0.5)
        finally:
            os.unlink(collector._path)

    def test_stop_interrupts_long_wait(self):
        collector = self.collector(interval=60)
        with patch.object(metrics, "WindowsMetrics", return_value=self.provider()):
            collector.start()
            try:
                deadline = time.monotonic() + 2
                while collector._path is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                collector.stop()
                collector.join(timeout=2)
                self.assertFalse(collector.is_alive())
            finally:
                collector.stop()
                collector.join(timeout=2)
                if collector._path:
                    os.unlink(collector._path)

    def test_native_windows_reads_current_process(self):
        provider = metrics.WindowsMetrics()
        self.assertEqual(len(provider.system_times()), 3)
        self.assertGreater(provider.memory()["total_physical_bytes"], 0)
        process = provider.process(os.getpid())
        self.assertGreater(process["creation_time_100ns"], 0)
        self.assertGreater(process["working_set_bytes"], 0)

    def test_native_handle_closed_if_process_times_fail(self):
        provider = metrics.WindowsMetrics()
        provider.kernel = Mock()
        provider.kernel.OpenProcess.return_value = 123
        provider.kernel.GetProcessTimes.return_value = False
        with self.assertRaises(OSError):
            provider.process(42)
        provider.kernel.CloseHandle.assert_called_once_with(123)

    def test_memory_failure_preserves_process_cpu_and_closes_handle(self):
        provider = metrics.WindowsMetrics()
        provider.kernel = Mock()
        provider.kernel.OpenProcess.return_value = 123
        provider.kernel.GetProcessTimes.return_value = True
        provider.psapi = Mock()
        provider.psapi.GetProcessMemoryInfo.return_value = False
        result = provider.process(42)
        self.assertIn("cpu_time_100ns", result)
        self.assertIn("memory_error", result)
        self.assertNotIn("working_set_bytes", result)
        provider.kernel.CloseHandle.assert_called_once_with(123)


if __name__ == "__main__":
    unittest.main()
