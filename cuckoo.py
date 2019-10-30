#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import argparse
import logging
import os
import sys

try:
    from lib.cuckoo.common.logo import logo
    from lib.cuckoo.common.config import Config
    from lib.cuckoo.common.constants import CUCKOO_VERSION, CUCKOO_ROOT
    from lib.cuckoo.common.exceptions import CuckooCriticalError
    from lib.cuckoo.common.exceptions import CuckooDependencyError
    from lib.cuckoo.core.database import Database
    from lib.cuckoo.core.startup import check_working_directory, check_configs, cuckoo_clean, cuckoo_clean_failed_tasks, cuckoo_clean_failed_url_tasks,cuckoo_clean_before_day,cuckoo_clean_sorted_pcap_dump,cuckoo_clean_bson_suri_logs, cuckoo_clean_pending_tasks
    from lib.cuckoo.core.startup import create_structure
    from lib.cuckoo.core.startup import init_logging, init_modules, init_console_logging
    from lib.cuckoo.core.startup import init_tasks, init_yara
    from lib.cuckoo.core.scheduler import Scheduler
    from lib.cuckoo.core.resultserver import ResultServer
    from lib.cuckoo.core.startup import init_rooter, init_routing

    import bson

    bson  # Pretend like it's actually being used (for static checkers.)
except (CuckooDependencyError, ImportError) as e:
    print("ERROR: Missing dependency: {0}".format(e))
    sys.exit()

log = logging.getLogger()

def cuckoo_init(quiet=False, debug=False, artwork=False, test=False):
    cur_path = os.getcwd()
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

    init_logging()

    if quiet:
        log.setLevel(logging.WARN)
    elif debug:
        log.setLevel(logging.DEBUG)

    init_modules()
    init_tasks()
    init_yara()
    init_rooter()
    init_routing()

    # This is just a temporary hack, we need an actual test suite to integrate
    # with Travis-CI.
    if test:
        return

    ResultServer()

    os.chdir(cur_path)

def cuckoo_main(max_analysis_count=0):
    cur_path = os.getcwd()
    os.chdir(CUCKOO_ROOT)

    try:
        sched = Scheduler(max_analysis_count)
        sched.start()
    except KeyboardInterrupt:
        sched.stop()

    os.chdir(cur_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-q", "--quiet", help="Display only error messages", action="store_true", required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-v", "--version", action="version", version="You are running Cuckoo Sandbox {0}".format(CUCKOO_VERSION))
    parser.add_argument("-a", "--artwork", help="Show artwork", action="store_true", required=False)
    parser.add_argument("-t", "--test", help="Test startup", action="store_true", required=False)
    parser.add_argument("-m", "--max-analysis-count", help="Maximum number of analyses", type=int, required=False)
    parser.add_argument("--clean", help="Remove all tasks and samples and their associated data", action='store_true', required=False)
    parser.add_argument("--failed-clean", help="Remove all tasks marked as failed", action='store_true', required=False)
    parser.add_argument("--failed-url-clean", help="Remove all tasks that are url tasks but we don't have any HTTP traffic", action='store_true', required=False)
    parser.add_argument("--delete-older-than-days", help="Remove all tasks older than X number of days", type=int, required=False)
    parser.add_argument("--pcap-sorted-clean", help="remove sorted pcap from jobs", action="store_true", required=False)
    parser.add_argument("--suricata-zero-alert-filter",help="only remove events with zero suri alerts DELETE AFTER ONLY", action="store_true", required=False)
    parser.add_argument("--urls-only-filter",help="only remove url events filter DELETE AFTER ONLY", action="store_true", required=False)
    parser.add_argument("--files-only-filter",help="only remove files events filter DELETE AFTER ONLY", action="store_true", required=False)
    parser.add_argument("--custom-include-filter",help="Only include jobs that match the custom field DELETE AFTER ONLY", required=False)
    parser.add_argument("--bson-suri-logs-clean",help="clean bson and suri logs from analysis dirs",required=False, action="store_true")
    parser.add_argument("--pending-clean",help="Remove all tasks marked as failed",required=False, action="store_true")
    args = parser.parse_args()

    if args.clean:
        cuckoo_clean()
        sys.exit(0)

    if args.failed_clean:
        cuckoo_clean_failed_tasks()
        sys.exit(0)

    if args.failed_url_clean:
        cuckoo_clean_failed_url_tasks()
        sys.exit(0)

    if args.delete_older_than_days:
        cuckoo_clean_before_day(args)
        sys.exit(0)

    if args.pcap_sorted_clean:
        cuckoo_clean_sorted_pcap_dump()
        sys.exit(0)

    if args.bson_suri_logs_clean:
        cuckoo_clean_bson_suri_logs()
        sys.exit(0)

    if args.pending_clean:
        cuckoo_clean_pending_tasks()
        sys.exit(0)

    try:
        cuckoo_init(quiet=args.quiet, debug=args.debug, artwork=args.artwork,
                    test=args.test)

        if not args.artwork and not args.test:
            cuckoo_main(max_analysis_count=args.max_analysis_count)
    except CuckooCriticalError as e:
        message = "{0}: {1}".format(e.__class__.__name__, e)
        if len(log.handlers):
            log.critical(message)
        else:
            sys.stderr.write("{0}\n".format(message))

        sys.exit(1)

