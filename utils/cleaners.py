# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import argparse
import os
import sys

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.cleaners_utils import execute_cleanup
from lib.cuckoo.core.database import init_database

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-tr", "--time-range", help="Time range can be specified as: 1d, 22h, 55m, etc", action="store", required=False
    )
    parser.add_argument(
        "--clean", help="Remove all tasks and samples and their associated data", action="store_true", required=False
    )
    parser.add_argument("--failed-clean", help="Remove all tasks marked as failed", action="store_true", required=False)
    parser.add_argument(
        "--failed-url-clean",
        help="Remove all tasks that are url tasks but we don't have any HTTP traffic",
        action="store_true",
        required=False,
    )
    parser.add_argument("--delete-older-than", help="Remove all tasks older than time range.", required=False)
    parser.add_argument("--pcap-sorted-clean", help="Remove sorted pcap from jobs", action="store_true", required=False)
    parser.add_argument(
        "--suricata-zero-alert-filter",
        help="only remove events with zero suri alerts DELETE AFTER ONLY",
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "--urls-only-filter", help="only remove url events filter DELETE AFTER ONLY", action="store_true", required=False
    )
    parser.add_argument(
        "--files-only-filter", help="only remove files events filter DELETE AFTER ONLY", action="store_true", required=False
    )
    parser.add_argument(
        "--custom-include-filter", help="Only include jobs that match the custom field DELETE AFTER ONLY", required=False
    )
    parser.add_argument(
        "--bson-suri-logs-clean", help="clean bson and suri logs from analysis dirs", required=False, action="store_true"
    )
    parser.add_argument("--pending-clean", help="Remove all tasks marked as pending", required=False, action="store_true")
    parser.add_argument("--malscore", help="Remove all tasks with malscore <= X", required=False, action="store", type=int)
    parser.add_argument("--tlp", help="Remove all tasks with TLP", required=False, default=False, action="store_true")
    parser.add_argument(
        "--delete-tmp-items-older-than",
        help="Remove all items in tmp folder older than time range",
        type=int,
        required=False,
    )
    parser.add_argument(
        "--delete-binaries-items-older-than",
        help="Remove all items in binaries folder older than time range",
        required=False,
    )
    parser.add_argument(
        "-dm", "--delete-mongo", help="Delete data in mongo. By default keep", required=False, default=False, action="store_true"
    )
    parser.add_argument(
        "-duf",
        "--delete-unused-file-data-in-mongo",
        help="Delete data from the 'files' collection in mongo that is no longer needed.",
        action="store_true",
    )
    # TODo move to start-end
    parser.add_argument(
        "-drs",
        "--delete-range",
        help="Delete jobs in range. Ex 1-5",
        action="store",
        required=False,
    )
    parser.add_argument(
        "-ddc",
        "--deduplicated-cluster-queue",
        help="Remove all pending duplicated jobs for our cluster, leave only 1 copy of task",
        action="store_true",
        required=False,
    )
    # ToDo
    parser.add_argument("-bt", "--before-time", help="Manage all pending jobs before X..", action="store", required=False)
    parser.add_argument(
        "-cmc",
        "--cleanup-mongo-calls",
        help="Manage all pending jobs before time range",
        action="store_true",
        required=False,
    )
    args = parser.parse_args()
    init_database()
    execute_cleanup(vars(args))
