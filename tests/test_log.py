import io
import json
import logging
from types import SimpleNamespace

from lib.cuckoo.core import log as cape_log


class _DummyStream(io.StringIO):
    def __init__(self, is_tty: bool = False):
        super().__init__()
        self._is_tty = is_tty

    def isatty(self) -> bool:
        return self._is_tty


def test_structured_json_formatter_single_line_and_context():
    formatter = cape_log.StructuredJsonFormatter(service_name="cape-processor")
    test_logger = logging.getLogger("modules.processing.CAPE")

    with cape_log.log_task_context(task_id=4242, main_task_id=9001, machine="win10_1"):
        record = test_logger.makeRecord(
            name="modules.processing.CAPE",
            level=logging.INFO,
            fn="/opt/CAPEv2/modules/processing/CAPE.py",
            lno=128,
            msg="Extracted config for %s",
            args=("sample.exe",),
            exc_info=None,
            func="run",
        )
        line = formatter.format(record)

    assert "\n" not in line
    payload = json.loads(line)
    assert payload["severity"] == "INFO"
    assert payload["message"] == "Extracted config for sample.exe"
    assert payload["service"] == "cape-processor"
    assert payload["logger"] == "modules.processing.CAPE"
    assert payload["task_id"] == 4242
    assert payload["main_task_id"] == 9001
    assert payload["machine"] == "win10_1"
    assert payload["logging.googleapis.com/sourceLocation"] == {
        "file": "/opt/CAPEv2/modules/processing/CAPE.py",
        "line": "128",
        "function": "run",
    }
    assert payload["logging.googleapis.com/labels"] == {
        "python_logger": "modules.processing.CAPE",
        "service": "cape-processor",
        "task_id": "4242",
        "main_task_id": "9001",
        "machine": "win10_1",
    }
    assert "@type" not in payload


def test_structured_json_formatter_exception_sets_reported_error_event():
    formatter = cape_log.StructuredJsonFormatter(service_name="cape")
    test_logger = logging.getLogger("lib.cuckoo.core.resultserver")

    try:
        raise FileExistsError("already exists")
    except FileExistsError:
        import sys

        exc_info = sys.exc_info()

    record = test_logger.makeRecord(
        name="lib.cuckoo.core.resultserver",
        level=logging.ERROR,
        fn="/opt/CAPEv2/lib/cuckoo/core/resultserver.py",
        lno=285,
        msg="Task #105: upload failed",
        args=(),
        exc_info=exc_info,
        func="handle",
    )
    line = formatter.format(record)
    assert "\n" not in line

    payload = json.loads(line)
    assert payload["severity"] == "ERROR"
    assert payload["task_id"] == 105
    assert payload["exception_type"] == "FileExistsError"
    assert "Traceback (most recent call last):" in payload["exception"]
    assert "FileExistsError: already exists" in payload["message"]
    assert payload["@type"] == cape_log.REPORTED_ERROR_EVENT_TYPE


def test_console_handler_and_colored_formatter_gate_ansi_on_tty(monkeypatch):
    monkeypatch.delenv("CAPE_COLOR_LOGS", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)

    non_tty = _DummyStream(is_tty=False)
    handler_non_tty = cape_log.ConsoleHandler(stream=non_tty)
    handler_non_tty.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    tty = _DummyStream(is_tty=True)
    handler_tty = cape_log.ConsoleHandler(stream=tty)
    handler_tty.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=10,
        msg="something failed",
        args=(),
        exc_info=None,
    )
    handler_non_tty.emit(record)
    handler_tty.emit(record)

    assert "\x1b[" not in non_tty.getvalue()
    assert "\x1b[" in tty.getvalue()

    dist_formatter_non_tty = cape_log.ColoredFormatter(fmt_with_thread=True, stream=non_tty)
    dist_formatter_tty = cape_log.ColoredFormatter(fmt_with_thread=True, stream=tty)
    dist_rec = logging.LogRecord(
        name="cuckoo.dist",
        level=logging.INFO,
        pathname=__file__,
        lineno=20,
        msg="[FETCH ] cape-worker-1 Task: 123 in 0.15s",
        args=(),
        exc_info=None,
    )
    assert "\x1b[" not in dist_formatter_non_tty.format(dist_rec)
    assert "\x1b[" in dist_formatter_tty.format(dist_rec)


def test_init_json_file_handler_writes_json_lines(tmp_path, monkeypatch):
    monkeypatch.setattr(cape_log, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setenv("CAPE_JSON_LOGS", "1")

    fake_logconf = SimpleNamespace(
        logger={"json_logs": True},
        log_rotation={"enabled": False, "backup_count": 7},
    )
    test_logger = logging.getLogger("test_cape_json_handler")
    test_logger.handlers[:] = []
    test_logger.setLevel(logging.INFO)
    test_logger.propagate = False

    jh = cape_log.init_json_file_handler(
        test_logger,
        "process.log",
        service_name="cape-processor",
        logconf=fake_logconf,
    )
    assert jh is not None
    try:
        with cape_log.log_task_context(task_id=777, main_task_id=888):
            test_logger.info("Processing started")
    finally:
        test_logger.removeHandler(jh)
        jh.close()

    json_log_file = tmp_path / "log" / "process.json.log"
    assert json_log_file.exists()
    lines = json_log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["message"] == "Processing started"
    assert parsed["task_id"] == 777
    assert parsed["main_task_id"] == 888
    assert parsed["service"] == "cape-processor"


def test_should_colorize_and_is_json_enabled_respect_config_and_int_values(monkeypatch):
    monkeypatch.delenv("CAPE_COLOR_LOGS", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("CAPE_JSON_LOGS", raising=False)

    non_tty = _DummyStream(is_tty=False)
    tty = _DummyStream(is_tty=True)

    # Fallback to Config("logging") when logconf=None
    monkeypatch.setattr(
        cape_log,
        "_resolve_logconf",
        lambda lc=None: lc if lc is not None else SimpleNamespace(logger={"color_logs": "on", "json_logs": 1}),
    )
    assert cape_log.should_colorize(non_tty) is True
    assert cape_log.is_json_logging_enabled() is True

    monkeypatch.setattr(
        cape_log,
        "_resolve_logconf",
        lambda lc=None: lc if lc is not None else SimpleNamespace(logger={"color_logs": 0, "json_logs": 0}),
    )
    assert cape_log.should_colorize(tty) is False
    assert cape_log.is_json_logging_enabled() is False


def test_structured_json_formatter_whole_second_and_surrogate_safety():
    formatter = cape_log.StructuredJsonFormatter(service_name="cape-processor")
    record = logging.LogRecord(
        name="test.surrogate",
        level=logging.WARNING,
        pathname=__file__,
        lineno=42,
        msg="unpacked file bad\udce2name.exe",
        args=(),
        exc_info=None,
    )
    # Exact integer second (.microsecond == 0) must still include .000000Z for fluentd %N
    record.created = 1700000000.0

    line = formatter.format(record)
    assert line.encode("utf-8")
    payload = json.loads(line)
    assert payload["time"] == "2023-11-14T22:13:20.000000Z"
    assert "\udce2" not in payload["message"]
    assert "bad?name.exe" in payload["message"]


def test_task_context_filter_and_message_regex_and_zero_sentinel():
    # Sentinel 0 / False values should not populate task_id / main_task_id
    with cape_log.log_task_context(task_id=0, main_task_id=False):
        ctx = cape_log.get_log_task_context()
        assert ctx["task_id"] is None
        assert ctx["main_task_id"] is None

    # Pebble supervisor timeout/exception message patterns and TaskContextFilter
    flt = cape_log.TaskContextFilter()
    rec = logging.LogRecord(
        name="lib.cuckoo.core.processing_engine.pebble",
        level=logging.ERROR,
        pathname=__file__,
        lineno=62,
        msg="[351234] Processing timeout: 300s",
        args=(),
        exc_info=None,
    )
    assert flt.filter(rec) is True
    assert getattr(rec, "task_id", None) == 351234

    # task_log_stop_force called from AnalysisManager thread must not wipe its log_task_context
    with cape_log.log_task_context(task_id=5555, machine="win10_2"):
        cape_log.task_log_stop_force(5555)
        assert cape_log.get_log_task_context()["task_id"] == 5555
        assert cape_log.get_log_task_context()["machine"] == "win10_2"

    # cuckoo.py Task #<id> (<main_task_id>) message format extracts both IDs
    cuckoo_rec = logging.LogRecord(
        name="lib.cuckoo.core.guest",
        level=logging.INFO,
        pathname=__file__,
        lineno=271,
        msg="Task #105 (9001): Starting analysis on guest (id=win10_1, ip=192.168.122.10)",
        args=(),
        exc_info=None,
    )
    assert flt.filter(cuckoo_rec) is True
    assert getattr(cuckoo_rec, "task_id", None) == 105
    assert getattr(cuckoo_rec, "main_task_id", None) == 9001

    # task_log_start binds both task_id and main_task_id in contextvars and task_log_stop clears both
    cape_log.task_log_start(105, main_task_id=9001)
    assert cape_log.get_log_task_context()["task_id"] == 105
    assert cape_log.get_log_task_context()["main_task_id"] == 9001
    cape_log.task_log_stop(105)
    assert cape_log.get_log_task_context()["task_id"] is None
    assert cape_log.get_log_task_context()["main_task_id"] is None
