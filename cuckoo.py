#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import logging
import os
import sys
from pathlib import Path

if sys.version_info[:2] < (3, 8):
    sys.exit("You are running an incompatible version of Python, please use >= 3.8")

if os.geteuid() == 0 and os.getenv("CAPE_AS_ROOT", "0") != "1":
    sys.exit("Root is not allowed. You gonna break permission and other parts of CAPE. RTM!")

from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooDependencyError

try:
    import bson

    from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
    from lib.cuckoo.common.logo import logo
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


def cuckoo_init(quiet=False, debug=False, artwork=False, test=False):
    cur_path = Path.cwd()
    os.chdir(CUCKOO_ROOT)

    logo()
    check_working_directory()
    check_configs()
    create_structure()

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

    check_webgui_mongo()
    init_modules()
    init_tasks()
    init_rooter()
    init_routing()
    check_tcpdump_permissions()

    # This is just a temporary hack, we need an actual test suite to integrate with Travis-CI.
    if test:
        return

    ResultServer()
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

    os.chdir(cur_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", help="Display only error messages", action="store_true", required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-v", "--version", action="version", version="You are running Cuckoo Sandbox {0}".format(CUCKOO_VERSION))
    parser.add_argument("-a", "--artwork", help="Show artwork", action="store_true", required=False)
    parser.add_argument("-t", "--test", help="Test startup", action="store_true", required=False)
    parser.add_argument("-m", "--max-analysis-count", help="Maximum number of analyses", type=int, required=False)
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
            message = "{0}: {1}".format(e.__class__.__name__, e)
            if any(filter(lambda hdlr: not isinstance(hdlr, logging.NullHandler), log.handlers)):
                log.critical(message)
            else:
                sys.stderr.write("{0}\n".format(message))

            sys.exit(1)
