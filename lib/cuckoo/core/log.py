# Copyright (C) 2016-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import contextvars
import copy
from datetime import datetime, timezone
import json
import logging
import logging.handlers
import os
import re
import sys
import threading
import time
from typing import Any, Iterator

import gevent.thread

from lib.cuckoo.common.colors import cyan, red, yellow
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.misc import cwd
from lib.cuckoo.common.path_utils import path_exists, path_mkdir
from lib.cuckoo.core.database import Database

_task_threads = {}
_tasks = {}
_loggers = {}

_tasks_lock = threading.Lock()

# Context variables for propagating task and worker metadata across log calls
_ctx_task_id: contextvars.ContextVar[int | None] = contextvars.ContextVar("cape_task_id", default=None)
_ctx_main_task_id: contextvars.ContextVar[int | None] = contextvars.ContextVar("cape_main_task_id", default=None)
_ctx_machine: contextvars.ContextVar[str | None] = contextvars.ContextVar("cape_machine", default=None)
_ctx_node: contextvars.ContextVar[str | None] = contextvars.ContextVar("cape_node", default=None)
_ctx_correlation_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("cape_correlation_id", default=None)

_RE_MSG_TASK = re.compile(
    r"(?:\bTask(?:\s+id|_id)?[\s:=]+#?(\d+)(?:\s+\((\d+)\))?|\[Task\s+(\d+)(?:\s+\((\d+)\))?\]"
    r"|\[(\d+)\]\s+(?:Processing timeout|Exception when processing task|Task never ran))",
    re.IGNORECASE,
)
_TRUTHY_VALUES = ("1", "true", "yes", "on", "always")
_FALSY_VALUES = ("0", "false", "no", "off", "never")

REPORTED_ERROR_EVENT_TYPE = (
    "type.googleapis.com/google.devtools.clouderrorreporting.v1beta1.ReportedErrorEvent"
)

# Current GMT+x.
if time.localtime().tm_isdst:
    tz = time.altzone / -3600.0
else:
    tz = time.timezone / -3600.0

# The greenlet library (used by Gevent) also creates some state per thread,
# so we can (ab)use this for both multi-threading and Gevent code
task_key = gevent.thread.get_ident


def _parse_positive_int(val: Any) -> int | None:
    if val is None or isinstance(val, bool):
        return None
    try:
        parsed = int(val)
        return parsed if parsed > 0 else None
    except (TypeError, ValueError):
        return None


def _resolve_logconf(logconf: Any = None) -> Any:
    if logconf is not None:
        return logconf
    with contextlib.suppress(Exception):
        from lib.cuckoo.common.config import Config

        return Config("logging")
    return None


def set_log_task_context(
    task_id: int | str | None = None,
    main_task_id: int | str | None = None,
    machine: str | None = None,
    node: str | None = None,
    correlation_id: str | None = None,
) -> None:
    """Bind task and machine context to the active thread/greenlet."""
    _ctx_task_id.set(_parse_positive_int(task_id))
    _ctx_main_task_id.set(_parse_positive_int(main_task_id))
    _ctx_machine.set(str(machine) if machine else None)
    _ctx_node.set(str(node) if node else None)
    _ctx_correlation_id.set(str(correlation_id) if correlation_id else None)


def clear_log_task_context() -> None:
    """Clear task and machine context from the active thread/greenlet."""
    _ctx_task_id.set(None)
    _ctx_main_task_id.set(None)
    _ctx_machine.set(None)
    _ctx_node.set(None)
    _ctx_correlation_id.set(None)


def get_log_task_context() -> dict[str, Any]:
    """Return currently bound task/machine logging context."""
    task_id = _ctx_task_id.get()
    if task_id is None:
        task_entry = _tasks.get(task_key())
        if task_entry:
            task_id = task_entry[0]
    return {
        "task_id": task_id,
        "main_task_id": _ctx_main_task_id.get(),
        "machine": _ctx_machine.get(),
        "node": _ctx_node.get(),
        "correlation_id": _ctx_correlation_id.get(),
    }


@contextlib.contextmanager
def log_task_context(
    task_id: int | str | None = None,
    main_task_id: int | str | None = None,
    machine: str | None = None,
    node: str | None = None,
    correlation_id: str | None = None,
) -> Iterator[None]:
    """Context manager to bind and automatically restore logging context."""
    prev = (
        _ctx_task_id.get(),
        _ctx_main_task_id.get(),
        _ctx_machine.get(),
        _ctx_node.get(),
        _ctx_correlation_id.get(),
    )
    set_log_task_context(
        task_id=task_id,
        main_task_id=main_task_id,
        machine=machine,
        node=node,
        correlation_id=correlation_id,
    )
    try:
        yield
    finally:
        _ctx_task_id.set(prev[0])
        _ctx_main_task_id.set(prev[1])
        _ctx_machine.set(prev[2])
        _ctx_node.set(prev[3])
        _ctx_correlation_id.set(prev[4])


def resolve_record_context(record: logging.LogRecord, message: str | None = None) -> dict[str, Any]:
    """Extract task, machine, node, and correlation context for a LogRecord."""
    ctx = get_log_task_context()
    rec_dict = record.__dict__

    rec_tid = _parse_positive_int(rec_dict.get("task_id"))
    task_id = rec_tid if rec_tid is not None else ctx["task_id"]
    rec_mtid = _parse_positive_int(rec_dict.get("main_task_id"))
    main_task_id = rec_mtid if rec_mtid is not None else ctx["main_task_id"]
    machine = rec_dict.get("machine") or ctx["machine"]
    node = rec_dict.get("node") or ctx["node"]
    correlation_id = rec_dict.get("correlation_id") or ctx["correlation_id"]

    if task_id is None or main_task_id is None:
        msg_text = message if message is not None else record.getMessage()
        match = _RE_MSG_TASK.search(msg_text)
        if match:
            if task_id is None:
                raw_tid = match.group(1) or match.group(3) or match.group(5)
                if raw_tid:
                    task_id = _parse_positive_int(raw_tid)
            if main_task_id is None:
                raw_mtid = match.group(2) or match.group(4)
                if raw_mtid:
                    main_task_id = _parse_positive_int(raw_mtid)

    return {
        "task_id": task_id,
        "main_task_id": main_task_id,
        "machine": machine,
        "node": node,
        "correlation_id": correlation_id,
    }


class TaskContextFilter(logging.Filter):
    """Filter that enriches LogRecords with active task/machine context attributes."""

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = resolve_record_context(record)
        for key, val in ctx.items():
            if val is not None and getattr(record, key, None) is None:
                setattr(record, key, val)
        return True


def should_colorize(stream: Any = None, logconf: Any = None) -> bool:
    """Return True if ANSI color sequences should be emitted to stream."""
    if os.getenv("NO_COLOR"):
        return False

    env_color = os.getenv("CAPE_COLOR_LOGS", "").strip().lower()
    if env_color:
        if env_color in _TRUTHY_VALUES:
            return True
        if env_color in _FALSY_VALUES:
            return False

    resolved_conf = _resolve_logconf(logconf)
    if resolved_conf is not None and hasattr(resolved_conf, "logger"):
        cfg_val = resolved_conf.logger.get("color_logs", "auto")
        if isinstance(cfg_val, (bool, int)):
            return bool(cfg_val)
        if isinstance(cfg_val, str):
            norm = cfg_val.strip().lower()
            if norm in _TRUTHY_VALUES:
                return True
            if norm in _FALSY_VALUES:
                return False

    target = stream if stream is not None else sys.stderr
    return bool(target is not None and hasattr(target, "isatty") and target.isatty())


def is_json_logging_enabled(logconf: Any = None) -> bool:
    """Return True if side-by-side JSON logging is enabled via env or logging.conf."""
    env_json = os.getenv("CAPE_JSON_LOGS", "").strip().lower()
    if env_json:
        if env_json in _TRUTHY_VALUES:
            return True
        if env_json in _FALSY_VALUES:
            return False

    resolved_conf = _resolve_logconf(logconf)
    if resolved_conf is not None and hasattr(resolved_conf, "logger"):
        val = resolved_conf.logger.get("json_logs", False)
        if isinstance(val, (bool, int)):
            return bool(val)
        if isinstance(val, str):
            return val.strip().lower() in _TRUTHY_VALUES
    return False


class DatabaseHandler(logging.Handler):
    """Logging to database handler.
    Used to log errors related to tasks in database.
    """

    def emit(self, record):
        # TODO Should this also attempt to guess the task ID from _tasks?
        if hasattr(record, "task_id") and record.task_id is not None:
            Database().add_error(self.format(record), int(record.task_id))


class TaskHandler(logging.Handler):
    """Per-task logger.
    Used to log all task specific events to a per-task cuckoo.log log file.
    """

    def emit(self, record):
        task = _tasks.get(task_key())
        if not task:
            return

        task[1].write(f"{self.format(record)}\n".encode())


class ConsoleHandler(logging.StreamHandler):
    """Logging to console handler with automatic TTY color detection."""

    def __init__(self, stream=None, colorize: bool | None = None):
        super().__init__(stream)
        self._colorize = colorize

    def emit(self, record):
        colored = copy.copy(record)
        if not isinstance(colored.msg, str):
            colored.msg = str(colored.msg)

        use_color = (
            self._colorize
            if self._colorize is not None
            else should_colorize(self.stream)
        )
        if use_color:
            if record.levelname == "WARNING":
                colored.msg = yellow(colored.msg)
            elif record.levelname in ("ERROR", "CRITICAL"):
                colored.msg = red(colored.msg)
            elif "analysis procedure completed" in colored.msg:
                colored.msg = cyan(colored.msg)

        logging.StreamHandler.emit(self, colored)


class ColoredFormatter(logging.Formatter):
    """Formatter for distributed and Pub/Sub services with TTY-gated ANSI highlighting."""

    GREY = "\x1b[38;20m"
    GREEN = "\x1b[32;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    CYAN = "\x1b[36;20m"
    RESET = "\x1b[0m"

    RE_WORKER = re.compile(r"\b(cape-worker[-\w]*)\b", re.IGNORECASE)
    RE_SETSTAT = re.compile(r"\b(task)\b\s+(\d+)\s+(status)", re.IGNORECASE)
    RE_MAIN_TASK = re.compile(
        r"\b(main(?:_task)?_id|main|analysis(?:[\s_-]?id)?|cape(?:[\s_-]?id)?)\b[:\s=]+([\d,]+)",
        re.IGNORECASE,
    )
    RE_WORKER_TASK = re.compile(
        r"\b(task(?:s|\(s\))?|task_id|worker(?:[\s_-]?id)?)\b[:\s=]+([\d,]+)",
        re.IGNORECASE,
    )
    RE_PERF = re.compile(r"\bin\s+([0-9.]+s)\b")

    def __init__(self, fmt_with_thread: bool = True, colorize: bool | None = None, stream: Any = None):
        super().__init__()
        self.fmt_with_thread = fmt_with_thread
        self._colorize = colorize
        self._stream = stream if stream is not None else sys.stdout
        if fmt_with_thread:
            self._plain_fmt = "%(asctime)s [%(levelname)-7s] %(module)-8s (%(threadName)s): %(message)s"
            self._colored_formats = {
                logging.DEBUG: f"%(asctime)s [{self.CYAN}%(levelname)-7s{self.RESET}] %(module)-8s (%(threadName)s): %(message)s",
                logging.INFO: f"%(asctime)s [{self.GREEN}%(levelname)-7s{self.RESET}] %(module)-8s (%(threadName)s): %(message)s",
                logging.WARNING: f"%(asctime)s [{self.YELLOW}%(levelname)-7s{self.RESET}] %(module)-8s (%(threadName)s): %(message)s",
                logging.ERROR: f"%(asctime)s [{self.RED}%(levelname)-7s{self.RESET}] %(module)-8s (%(threadName)s): %(message)s",
                logging.CRITICAL: f"%(asctime)s [{self.BOLD_RED}%(levelname)-7s{self.RESET}] %(module)-8s (%(threadName)s): %(message)s",
            }
        else:
            self._plain_fmt = "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
            self._colored_formats = {
                logging.DEBUG: f"%(asctime)s [{self.CYAN}%(levelname)-7s{self.RESET}] %(name)s: %(message)s",
                logging.INFO: f"%(asctime)s [{self.GREEN}%(levelname)-7s{self.RESET}] %(name)s: %(message)s",
                logging.WARNING: f"%(asctime)s [{self.YELLOW}%(levelname)-7s{self.RESET}] %(name)s: %(message)s",
                logging.ERROR: f"%(asctime)s [{self.RED}%(levelname)-7s{self.RESET}] %(name)s: %(message)s",
                logging.CRITICAL: f"%(asctime)s [{self.BOLD_RED}%(levelname)-7s{self.RESET}] %(name)s: %(message)s",
            }

        self._plain_formatter = logging.Formatter(self._plain_fmt)
        self._colored_formatters = {
            lvl: logging.Formatter(fmt) for lvl, fmt in self._colored_formats.items()
        }

    def format(self, record: logging.LogRecord) -> str:
        use_color = (
            self._colorize
            if self._colorize is not None
            else should_colorize(self._stream)
        )
        if not use_color:
            return self._plain_formatter.format(record)

        formatter = self._colored_formatters.get(record.levelno, self._plain_formatter)
        formatted_message = formatter.format(record)

        bold_cyan = "\x1b[36;1m"
        bold_green = "\x1b[32;1m"
        bold_yellow = "\x1b[33;1m"
        bold_magenta = "\x1b[35;1m"
        bold_blue = "\x1b[34;1m"
        bold_red = "\x1b[31;1m"
        cyan_code = "\x1b[36m"
        green_code = "\x1b[32m"
        yellow_code = "\x1b[33m"
        magenta_code = "\x1b[35m"
        reset = "\x1b[0m"

        formatted_message = self.RE_WORKER.sub(rf"{cyan_code}\1{reset}", formatted_message)
        formatted_message = self.RE_SETSTAT.sub(rf"\1 {magenta_code}\2{reset} \3", formatted_message)
        formatted_message = self.RE_MAIN_TASK.sub(rf"\1: {magenta_code}\2{reset}", formatted_message)
        formatted_message = self.RE_WORKER_TASK.sub(rf"\1: {yellow_code}\2{reset}", formatted_message)
        formatted_message = self.RE_PERF.sub(rf"in {green_code}\1{reset}", formatted_message)

        replacements = {
            "[FETCH ]": f"{bold_green}[FETCH ]{reset}",
            "[SUBMIT]": f"{bold_cyan}[SUBMIT]{reset}",
            "[REMOVE]": f"{bold_red}[REMOVE]{reset}",
            "[GCS   ]": f"{bold_magenta}[GCS   ]{reset}",
            "[PERF  ]": f"{bold_yellow}[PERF  ]{reset}",
        }
        for old, new in replacements.items():
            if old in formatted_message:
                formatted_message = formatted_message.replace(old, new)

        if "STATUS | " in formatted_message:
            formatted_message = formatted_message.replace("STATUS |", f"{bold_blue}STATUS{reset} |")
            formatted_message = formatted_message.replace("Pend:", f"{bold_yellow}Pend:{reset}")
            formatted_message = formatted_message.replace("Run:", f"{bold_green}Run:{reset}")
            formatted_message = formatted_message.replace("Done:", f"{bold_blue}Done:{reset}")
            formatted_message = formatted_message.replace("Rep:", f"{bold_magenta}Rep:{reset}")

        return formatted_message


class JsonFormatter(logging.Formatter):
    """Logging Cuckoo action/status logs to JSON."""

    def format(self, record):
        action = record.__dict__.get("action")
        status = record.__dict__.get("status")
        task = _tasks.get(task_key())
        task_id = task[0] if task else record.__dict__.get("task_id")
        d = {
            "action": action,
            "task_id": task_id,
            "status": status,
            "time": record.created,
            "level": record.levelname.lower(),
            "message": record.getMessage(),
        }
        base = logging.makeLogRecord({})
        for key, value in record.__dict__.items():
            if key not in base.__dict__:
                d[key] = value
        return json.dumps(d)

    def filter(self, record):
        action = record.__dict__.get("action")
        status = record.__dict__.get("status")
        return action and status


class StructuredJsonFormatter(logging.Formatter):
    """Single-line structured JSON formatter compatible with google-fluentd and Cloud Logging."""

    def __init__(self, service_name: str = "cape"):
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        base_msg = record.getMessage()
        ctx = resolve_record_context(record, message=base_msg)

        exc_text = None
        exc_type_name = None
        if record.exc_info:
            if record.exc_info[0] is not None:
                exc_type_name = record.exc_info[0].__name__
            exc_text = self.formatException(record.exc_info)
        elif record.exc_text:
            exc_text = record.exc_text

        full_message = base_msg
        if exc_text:
            full_message = f"{base_msg}\n{exc_text}" if base_msg else exc_text
        if record.stack_info:
            stack_str = self.formatStack(record.stack_info)
            full_message = f"{full_message}\n{stack_str}" if full_message else stack_str

        iso_time = (
            datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )

        labels: dict[str, str] = {
            "python_logger": record.name,
            "service": self.service_name,
        }
        if ctx["task_id"] is not None:
            labels["task_id"] = str(ctx["task_id"])
        if ctx["main_task_id"] is not None:
            labels["main_task_id"] = str(ctx["main_task_id"])
        if ctx["machine"]:
            labels["machine"] = str(ctx["machine"])
        if ctx["node"]:
            labels["node"] = str(ctx["node"])
        if ctx["correlation_id"]:
            labels["correlation_id"] = str(ctx["correlation_id"])

        payload: dict[str, Any] = {
            "time": iso_time,
            "severity": record.levelname,
            "message": full_message,
            "logger": record.name,
            "service": self.service_name,
            "pid": record.process,
            "process_name": record.processName,
            "thread": record.threadName,
            "logging.googleapis.com/sourceLocation": {
                "file": record.pathname,
                "line": str(record.lineno),
                "function": record.funcName,
            },
            "logging.googleapis.com/labels": labels,
        }

        for key in ("task_id", "main_task_id", "machine", "node", "correlation_id"):
            if ctx[key] is not None:
                payload[key] = ctx[key]

        if exc_text:
            payload["exception"] = exc_text
        if exc_type_name:
            payload["exception_type"] = exc_type_name

        if record.levelno >= logging.ERROR and (
            exc_text or record.stack_info or "Traceback (most recent call last):" in full_message
        ):
            payload["@type"] = REPORTED_ERROR_EVENT_TYPE

        out = json.dumps(payload, default=str, ensure_ascii=False)
        try:
            out.encode("utf-8")
        except UnicodeEncodeError:
            out = out.encode("utf-8", errors="replace").decode("utf-8")
        return out


def init_json_file_handler(
    logger_obj: logging.Logger,
    log_filename: str,
    service_name: str = "cape",
    logconf: Any = None,
    handler_cls: type[logging.Handler] | None = None,
    backup_count: int | None = None,
    watch_only: bool = False,
    cuckoo_root: str | None = None,
) -> logging.Handler | None:
    """Attach a rotated side-by-side <stem>.json.log handler when json_logs is enabled."""
    if not is_json_logging_enabled(logconf):
        return None

    log_dir = os.path.join(cuckoo_root or CUCKOO_ROOT, "log")
    if not path_exists(log_dir):
        path_mkdir(log_dir)

    stem = log_filename[:-4] if log_filename.endswith(".log") else log_filename
    json_path = os.path.join(log_dir, f"{stem}.json.log")

    # Remove existing StructuredJsonFormatter handlers for this file to keep init idempotent
    for existing in list(logger_obj.handlers):
        if (
            isinstance(getattr(existing, "formatter", None), StructuredJsonFormatter)
            and getattr(existing, "baseFilename", None) == os.path.abspath(json_path)
        ):
            if watch_only:
                logger_obj.handlers.remove(existing)
            else:
                logger_obj.removeHandler(existing)
                existing.close()

    rotation_enabled = True
    days = backup_count or 7
    if logconf is not None and hasattr(logconf, "log_rotation"):
        rotation_enabled = bool(logconf.log_rotation.get("enabled", True))
        if backup_count is None:
            days = int(logconf.log_rotation.get("backup_count", 7) or 7)

    if watch_only or not rotation_enabled:
        jh: logging.Handler = logging.handlers.WatchedFileHandler(json_path)
    else:
        cls = handler_cls or logging.handlers.TimedRotatingFileHandler
        jh = cls(json_path, when="midnight", backupCount=int(days))

    jh.setFormatter(StructuredJsonFormatter(service_name=service_name))
    if watch_only:
        logger_obj.handlers.append(jh)
    else:
        logger_obj.addHandler(jh)
    return jh


def task_log_start(task_id, main_task_id=None):
    """Associate a thread with a task."""
    _ctx_task_id.set(_parse_positive_int(task_id))
    _ctx_main_task_id.set(_parse_positive_int(main_task_id))
    _tasks_lock.acquire()
    try:
        if task_id not in _task_threads:
            task_path = cwd(analysis=task_id)
            if not path_exists(task_path):
                return

            _task_threads[task_id] = []
            fp = open(os.path.join(task_path, "cuckoo.log"), "a+b")
            _tasks[task_key()] = (task_id, fp)
        else:
            existing_key = _task_threads[task_id][0]
            _tasks[task_key()] = _tasks[existing_key]

        _task_threads[task_id].append(task_key())
    finally:
        _tasks_lock.release()


def task_log_stop(task_id):
    """Disassociate a thread from a task."""
    _ctx_task_id.set(None)
    _ctx_main_task_id.set(None)
    _tasks_lock.acquire()
    try:
        thread_key = task_key()
        if thread_key not in _tasks:
            return

        _, fp = _tasks.pop(thread_key)
        _task_threads[task_id].remove(thread_key)
        if not _task_threads[task_id]:
            fp.close()
            _task_threads.pop(task_id)
    finally:
        _tasks_lock.release()


def task_log_stop_force(task_id):
    """Force disassociate all threads from a task and close the log file."""
    _tasks_lock.acquire()
    try:
        if task_id not in _task_threads:
            return

        # Close the file handle (shared by all threads for this task)
        # We can take it from any associated thread
        if _task_threads[task_id]:
            first_key = _task_threads[task_id][0]
            if first_key in _tasks:
                _, fp = _tasks[first_key]
                try:
                    fp.close()
                except Exception as e:
                    logging.warning("Failed to force-close log for task %d: %s", task_id, e)

        # Cleanup all references
        for thread_key in _task_threads[task_id]:
            _tasks.pop(thread_key, None)

        _task_threads.pop(task_id, None)
    finally:
        _tasks_lock.release()


def init_logger(name, level=None):
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    if name == "console":
        logger = ConsoleHandler()
        logger.setFormatter(formatter)
        logger.setLevel(level)

    elif name == "database":
        logger = DatabaseHandler()
        logger.setLevel(logging.ERROR)

    elif name == "task":
        logger = TaskHandler()
        logger.setFormatter(formatter)
        logger.setLevel(logging.DEBUG)

    _loggers[name] = logger
    logging.getLogger().addHandler(logger)


def logger(message, *args, **kwargs):
    """Log a message to specific logger instance."""
    logfile = kwargs.pop("logfile", None)
    record = logging.LogRecord(None, logging.INFO, None, None, message, args, None, None)
    record.asctime = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record.created))},{record.msecs:03d}"
    record.message = record.getMessage()
    record.__dict__.update(kwargs)

    for key, value in _loggers.items():
        if logfile and key == logfile:
            value.handle(record)
        if logfile is None and key.endswith(".json"):
            value.handle(record)

