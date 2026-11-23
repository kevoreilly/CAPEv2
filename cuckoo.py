#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import logging
import os
import sys
from contextlib import suppress
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None

if os.geteuid() == 0 and os.getenv("CAPE_AS_ROOT", "0") != "1":
    sys.exit("Root is not allowed. You gonna break permission and other parts of CAPE. RTM!")

from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooDependencyError, CuckooStartupError

try:
    import bson

    from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
    from lib.cuckoo.common.logo import logo
    from lib.cuckoo.core.database import Database, init_database
    from lib.cuckoo.core.resultserver import ResultServer
    from lib.cuckoo.core.scheduler import Scheduler
    from lib.cuckoo.core.startup import (
        check_configs,
        check_linux_dist,
        check_tcpdump_permissions,
        check_webgui_mongo,
        check_working_directory,
        create_structure,
        init_logging,
        init_modules,
        init_rooter,
        init_routing,
        init_tasks,
    )

    bson  # Pretend like it's actually being used (for static checkers.)
except (CuckooDependencyError, ImportError) as e:
    print(f"ERROR: Missing dependency: {e}")
    sys.exit()

log = logging.getLogger()

check_linux_dist()

_CUCKOO_LOCK_FD = None


def _close_cuckoo_lock_in_child():
    """Close inherited instance lock descriptor in forked children so child processes
    never keep cuckoo.lock held after the scheduler exits."""
    global _CUCKOO_LOCK_FD
    fd = _CUCKOO_LOCK_FD
    _CUCKOO_LOCK_FD = None
    if fd is not None:
        with suppress(OSError):
            fd.close()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_close_cuckoo_lock_in_child)


def _acquire_cuckoo_lock(cuckoo_root: str | None = None):
    """Acquire a non-blocking single-instance flock before mutating live tasks or routing."""
    global _CUCKOO_LOCK_FD
    if fcntl is None:
        return None
    if _CUCKOO_LOCK_FD is not None:
        return _CUCKOO_LOCK_FD

    if cuckoo_root is None:
        cuckoo_root = CUCKOO_ROOT
    lock_dir = os.path.join(cuckoo_root, "log")
    lock_path = os.path.join(lock_dir, "cuckoo.lock")
    raw_fd = None
    lock_file = None
    try:
        os.makedirs(lock_dir, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        raw_fd = os.open(lock_path, flags, 0o600)
        lock_file = os.fdopen(raw_fd, "r+")
        raw_fd = None
    except OSError as err:
        if raw_fd is not None:
            with suppress(OSError):
                os.close(raw_fd)
        log.warning("Unable to open CAPE instance lockfile %s (%s); continuing unlocked", lock_path, err)
        return None

    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        holder_pid = ""
        with suppress(OSError):
            lock_file.seek(0)
            holder_pid = lock_file.read(32).strip()
        with suppress(OSError):
            lock_file.close()
        pid_info = f" (PID {holder_pid})" if holder_pid.isdigit() else ""
        raise CuckooStartupError(
            f"Another CAPE instance is already running{pid_info} (lock held on {lock_path}).\n"
            "This usually happens because CAPE is already running in the background as cape.service.\n"
            "Run 'sudo systemctl stop cape.service' to stop the background service, "
            "or use the running background service instead of starting another instance here."
        ) from None
    except OSError as err:
        with suppress(OSError):
            lock_file.close()
        log.warning("flock unavailable on %s (%s); continuing unlocked", lock_path, err)
        return None

    with suppress(OSError):
        lock_file.seek(0)
        lock_file.truncate()
        lock_file.write(f"{os.getpid()}\n")
        lock_file.flush()

    _CUCKOO_LOCK_FD = lock_file
    return lock_file


def _release_cuckoo_lock():
    """Release and close the single-instance lock if currently held."""
    global _CUCKOO_LOCK_FD
    fd = _CUCKOO_LOCK_FD
    _CUCKOO_LOCK_FD = None
    if fd is not None:
        with suppress(OSError):
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
        with suppress(OSError):
            fd.close()


def _log_critical_error(exc: CuckooCriticalError, debug: bool = False):
    """Log a CuckooCriticalError cleanly (omitting traceback noise for expected startup errors unless debug=True)."""
    message = f"{exc.__class__.__name__}: {exc}"
    show_traceback = debug or not isinstance(exc, CuckooStartupError)
    if any(not isinstance(hdlr, logging.NullHandler) for hdlr in log.handlers):
        log.critical("%s", message, exc_info=show_traceback)
    else:
        sys.stderr.write(f"{message}\n")


def cuckoo_init(quiet=False, debug=False, artwork=False, test=False):
    cur_path = Path.cwd()
    os.chdir(CUCKOO_ROOT)
    try:
        logo()
        check_working_directory()
        check_configs()
        create_structure()
        init_database()

        if artwork:
            import time

            try:
                while True:
                    time.sleep(1)
                    logo()
            except KeyboardInterrupt:
                return

        if quiet:
            level = logging.WARN
        elif debug:
            level = logging.DEBUG
        else:
            level = logging.INFO
        log.setLevel(level)
        init_logging(level)

        _acquire_cuckoo_lock()
        try:
            check_webgui_mongo()
            init_modules()
            with Database().session.begin():
                init_tasks()
            init_rooter(apply_state=True)  # scheduler owns the rooter state reset (codex P1)
            init_routing(apply_nexthop_state=True)  # scheduler owns the nexthop sweep/build/arm (codex P2)
            check_tcpdump_permissions()

            # This is just a temporary hack, we need an actual test suite to integrate with Travis-CI.
            if test:
                _release_cuckoo_lock()
                return

            ResultServer()
        except BaseException:
            _release_cuckoo_lock()
            raise
    finally:
        os.chdir(cur_path)


def cuckoo_main(max_analysis_count=0):
    cur_path = Path.cwd()
    os.chdir(CUCKOO_ROOT)

    sched = Scheduler(max_analysis_count)
    try:
        sched.start()
    except KeyboardInterrupt:
        log.info("Received keyboard interrupt, stopping.")
    finally:
        sched.shutdown_machinery()
        ResultServer.shutdown_if_running()
        _release_cuckoo_lock()
        os.chdir(cur_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", help="Display only error messages", action="store_true", required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-v", "--version", action="version", version="You are running Cuckoo Sandbox {0}".format(CUCKOO_VERSION))
    parser.add_argument("-a", "--artwork", help="Show artwork", action="store_true", required=False)
    parser.add_argument("-t", "--test", help="Test startup", action="store_true", required=False)
    parser.add_argument("-m", "--max-analysis-count", help="Maximum number of analyses", type=int, required=False, default=0)
    parser.add_argument(
        "-s",
        "--stop",
        help="Send signal to STOP analyzing upcoming tasks. Finish existent tasks and quit. Proper restart to pick any core changes.",
        action="store_true",
        required=False,
    )
    args = parser.parse_args()

    if args.stop:
        import psutil

        filename = Path(__file__).parts[-1]
        for p in psutil.process_iter(attrs=["name", "pid", "cmdline"]):
            # cuckoo.py but doing in this way in case we rename it in future
            if filename in p.info["cmdline"]:
                p.send_signal(1)
                break
    else:
        try:
            cuckoo_init(quiet=args.quiet, debug=args.debug, artwork=args.artwork, test=args.test)
            if not args.artwork and not args.test:
                cuckoo_main(max_analysis_count=args.max_analysis_count)
        except CuckooCriticalError as e:
            _log_critical_error(e, debug=args.debug)
            sys.exit(1)
