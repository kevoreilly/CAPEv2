#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import argparse
import fnmatch
import logging
import os
import random
import sys

try:
    import requests

    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.colors import bold, green, red, yellow
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import to_unicode
from lib.cuckoo.core.database import Database
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooDemuxError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="URL, path to the file or folder to analyze")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--remote", type=str, action="store", default=None, help="Specify IP:port to a Cuckoo API server to submit remotely", required=False
    )
    parser.add_argument("--user", type=str, action="store", default=None, help="Username for Basic Auth", required=False)
    parser.add_argument("--password", type=str, action="store", default=None, help="Password for Basic Auth", required=False)
    parser.add_argument("--sslnoverify", action="store_true", default=False, help="Do not validate SSL cert", required=False)
    parser.add_argument("--ssl", action="store_true", default=False, help="Use SSL/TLS for remote", required=False)
    parser.add_argument("--url", action="store_true", default=False, help="Specify whether the target is an URL", required=False)
    parser.add_argument("--package", type=str, action="store", default="", help="Specify an analysis package", required=False)
    parser.add_argument("--custom", type=str, action="store", default="", help="Specify any custom value", required=False)
    parser.add_argument("--timeout", type=int, action="store", default=0, help="Specify an analysis timeout", required=False)
    parser.add_argument(
        "--options",
        type=str,
        action="store",
        default="",
        help='Specify options for the analysis package (e.g. "name=value,name2=value2")',
        required=False,
    )
    parser.add_argument(
        "--priority", type=int, action="store", default=1, help="Specify a priority for the analysis represented by an integer", required=False
    )
    parser.add_argument(
        "--machine", type=str, action="store", default="", help="Specify the identifier of a machine you want to use", required=False
    )
    parser.add_argument(
        "--platform",
        type=str,
        action="store",
        default="",
        help="Specify the operating system platform you want to use (windows/darwin/linux)",
        required=False,
    )
    parser.add_argument(
        "--memory", action="store_true", default=False, help="Enable to take a memory dump of the analysis machine", required=False
    )
    parser.add_argument(
        "--enforce-timeout",
        action="store_true",
        default=False,
        help="Enable to force the analysis to run for the full timeout period",
        required=False,
    )
    parser.add_argument("--clock", type=str, action="store", default=None, help="Set virtual machine clock", required=False)
    parser.add_argument(
        "--tags", type=str, action="store", default=None, help="Specify tags identifier of a machine you want to use", required=False
    )
    parser.add_argument("--max", type=int, action="store", default=None, help="Maximum samples to add in a row", required=False)
    parser.add_argument("--pattern", type=str, action="store", default=None, help="Pattern of files to submit", required=False)
    parser.add_argument("--shuffle", action="store_true", default=False, help="Shuffle samples before submitting them", required=False)
    parser.add_argument("--unique", action="store_true", default=False, help="Only submit new samples, ignore duplicates", required=False)
    parser.add_argument("--quiet", action="store_true", default=False, help="Only print text on failure", required=False)
    parser.add_argument("--procdump", action="store_true", default=False, help="Dump, upload and process proc/memdumps", required=False)

    try:
        args = parser.parse_args()
    except IOError as e:
        parser.error(e)
        return False

    # If the quiet flag has been set, then we also disable the "warning"
    # level of the logging module. (E.g., when pydeep has not been installed,
    # there will be a warning message, because Cuckoo can't resolve the
    # ssdeep hash of this particular sample.)
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig()

    if args.quiet:
        logging.disable(logging.WARNING)

    db = Database()

    target = to_unicode(args.target)

    sane_timeout = min(args.timeout, 60 * 60 * 24)

    if args.procdump:
        if args.options:
            args.options = ",procdump=1"
        else:
            args.options = "procdump=1"

    if args.url:
        if args.remote:
            if not HAVE_REQUESTS:
                print((bold(red("Error")) + ": you need to install python-requests (`pip3 install requests`)"))
                return False

            if args.ssl:
                url = "https://{0}/tasks/create/url".format(args.remote)
            else:
                url = "http://{0}/tasks/create/url".format(args.remote)

            data = dict(
                url=target,
                package=args.package,
                timeout=sane_timeout,
                options=args.options,
                priority=args.priority,
                machine=args.machine,
                platform=args.platform,
                memory=args.memory,
                enforce_timeout=args.enforce_timeout,
                custom=args.custom,
                tags=args.tags,
            )

            try:
                if args.user and args.password:
                    if args.ssl:
                        if args.sslnoverify:
                            verify = False
                        else:
                            verify = True
                        response = requests.post(url, auth=(args.user, args.password), data=data, verify=verify)
                    else:
                        response = requests.post(url, auth=(args.user, args.password), data=data)
                else:
                    if args.ssl:
                        if args.sslnoverify:
                            verify = False
                        else:
                            verify = True
                        response = requests.post(url, data=data, verify=verify)
                    else:
                        response = requests.post(url, data=data)

            except Exception as e:
                print((bold(red("Error")) + ": unable to send URL: {0}".format(e)))
                return False

            json = response.json()
            task_id = json["task_id"]
        else:
            task_id = db.add_url(
                target,
                package=args.package,
                timeout=sane_timeout,
                options=args.options,
                priority=args.priority,
                machine=args.machine,
                platform=args.platform,
                custom=args.custom,
                memory=args.memory,
                enforce_timeout=args.enforce_timeout,
                clock=args.clock,
                tags=args.tags,
            )

        if task_id:
            if not args.quiet:
                print((bold(green("Success")) + u': URL "{0}" added as task with ID {1}'.format(target, task_id)))
        else:
            print((bold(red("Error")) + ": adding task to database"))
    else:
        # Get absolute path to deal with relative.
        path = to_unicode(os.path.abspath(target))
        if not os.path.exists(path):
            print((bold(red("Error")) + u': the specified file/folder does not exist at path "{0}"'.format(path)))
            return False

        files = []
        if os.path.isdir(path):
            for dirname, _, filenames in os.walk(path):
                for file_name in filenames:
                    file_path = os.path.join(dirname, file_name)

                    if os.path.isfile(file_path):
                        if args.pattern:
                            if fnmatch.fnmatch(file_name, args.pattern):
                                files.append(to_unicode(file_path))
                        else:
                            files.append(to_unicode(file_path))
        else:
            files.append(path)

        if args.shuffle:
            random.shuffle(files)
        else:
            files = sorted(files)

        for file_path in files:
            if not File(file_path).get_size():
                if not args.quiet:
                    print((bold(yellow("Empty") + ": sample {0} (skipping file)".format(file_path))))

                continue

            if args.max is not None:
                # Break if the maximum number of samples has been reached.
                if not args.max:
                    break

                args.max -= 1

            if args.remote:
                if not HAVE_REQUESTS:
                    print((bold(red("Error")) + ": you need to install python-requests (`pip3 install requests`)"))
                    return False
                if args.ssl:
                    url = "https://{0}/tasks/create/file".format(args.remote)
                else:
                    url = "http://{0}/tasks/create/file".format(args.remote)

                files = dict(file=open(file_path, "rb"), filename=os.path.basename(file_path))

                data = dict(
                    package=args.package,
                    timeout=sane_timeout,
                    options=args.options,
                    priority=args.priority,
                    machine=args.machine,
                    platform=args.platform,
                    memory=args.memory,
                    enforce_timeout=args.enforce_timeout,
                    custom=args.custom,
                    tags=args.tags,
                )

                try:
                    if args.user and args.password:
                        if args.ssl:
                            if args.sslnoverify:
                                verify = False
                            else:
                                verify = True
                            response = requests.post(url, auth=(args.user, args.password), files=files, data=data, verify=verify)
                        else:
                            response = requests.post(url, auth=(args.user, args.password), files=files, data=data)
                    else:
                        if args.ssl:
                            if args.sslnoverify:
                                verify = False
                            else:
                                verify = True
                            response = requests.post(url, files=files, data=data, verify=verify)
                        else:
                            response = requests.post(url, files=files, data=data)

                except Exception as e:
                    print((bold(red("Error")) + ": unable to send file: {0}".format(e)))
                    return False

                json = response.json()
                task_ids = [json.get("task_ids", None)]

            else:
                if args.unique and db.check_file_uniq(File(file_path).get_sha256()):
                    msg = ": Sample {0} (skipping file)".format(file_path)
                    if not args.quiet:
                        print((bold(yellow("Duplicate")) + msg))
                    continue

                try:
                    task_ids, extra_details = db.demux_sample_and_add_to_db(
                        file_path=file_path.encode("utf-8"),
                        package=args.package,
                        timeout=sane_timeout,
                        options=args.options,
                        priority=args.priority,
                        machine=args.machine,
                        platform=args.platform,
                        memory=args.memory,
                        custom=args.custom,
                        enforce_timeout=args.enforce_timeout,
                        clock=args.clock,
                        tags=args.tags,
                    )
                except CuckooDemuxError as e:
                    task_ids = []
                    print((bold(red("Error")) + ": {0}".format(e)))
            tasks_count = len(task_ids)
            if tasks_count > 1:
                if not args.quiet:
                    print((bold(green("Success")) + u': File "{0}" added as task with IDs {1}'.format(file_path, task_ids)))
            elif tasks_count > 0:
                if not args.quiet:
                    print((bold(green("Success")) + u': File "{0}" added as task with ID {1}'.format(file_path, task_ids[0])))
            else:
                print((bold(red("Error")) + ": adding task to database"))


if __name__ == "__main__":
    main()
