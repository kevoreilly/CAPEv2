#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys

if sys.version_info[:2] < (3, 6):
    sys.exit("You are running an incompatible version of Python, please use >= 3.6")
import logging
import shutil
import urllib3
import argparse
import tempfile
import tarfile
from io import BytesIO

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

import lib.cuckoo.common.colors as colors
from lib.cuckoo.common.constants import CUCKOO_ROOT
log = logging.getLogger(__name__)
URL = "https://github.com/kevoreilly/community/archive/{0}.tar.gz"

def install(enabled, force, rewrite, filepath):
    if filepath and os.path.exists(filepath):
        data = open(filepath, "rb").read()
    else:
        print("Downloading modules from {0}".format(URL))
        try:
            http = urllib3.PoolManager()
            data = http.request('GET', URL).data
            t = tarfile.TarFile.open(fileobj=BytesIO(data), mode="r:gz")
        except Exception as e:
            print("ERROR: Unable to download archive: %s" % e)
            sys.exit(-1)

    folders = {
        "feeds": "modules/feeds",
        "signatures": "modules/sigantures",
        "processing": "modules/processing",
        "reporting":  "modules/reporting",
        "machinery":  "modules/machinery",
        "analyzer": "analyzer",
        "data": "data",
    }

    members = t.getmembers()
    directory = members[0].name.split("/")[0]

    for category in enabled:
        folder = folders.get(category, False)
        if not folder:
            continue

        print("\nInstalling {0}".format(colors.cyan(category.upper())))
        for _, outfolder in folders.items():

            # E.g., "community-master/modules/signatures".
            name_start = "%s/%s" % (directory, outfolder)
            for member in members:
                if not member.name.startswith(name_start) or name_start == member.name:
                    continue

                filepath = os.path.join(CUCKOO_ROOT, outfolder, member.name[len(name_start)+1:])
                if member.name.endswith(".gitignore"):
                    continue

                if member.isdir():
                    if not os.path.exists(filepath):
                        os.mkdir(filepath)
                    continue

                if not rewrite:
                    if os.path.exists(filepath):
                        print("File \"{0}\" already exists, {1}".format(filepath, colors.yellow("skipped")))
                        continue

                install = False
                dest_file = os.path.basename(filepath)
                if not force:
                    while 1:
                        choice = input("Do you want to install file " "\"{0}\"? [yes/no] ".format(dest_file))
                        if choice.lower() == "yes":
                            install = True
                            break
                        elif choice.lower() == "no":
                            break
                        else:
                            continue
                else:
                    install = True

                if install:
                    if not os.path.exists(os.path.dirname(filepath)):
                        os.makedirs(os.path.dirname(filepath))

                    print("File \"{0}\" {1}".format(filepath, colors.green("installed")))
                    open(filepath, "wb").write(t.extractfile(member).read())

def main():
    global URL

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--all", help="Download everything", action="store_true", required=False)
    parser.add_argument("-e", "--feeds", help="Download CAPE feed modules", action="store_true", required=False)
    parser.add_argument("-s", "--signatures", help="Download CAPE signatures", action="store_true", required=False)
    parser.add_argument("-p", "--processing", help="Download processing modules", action="store_true", required=False)
    parser.add_argument("-m", "--machinery", help="Download machine managers",action="store_true", required=False)
    parser.add_argument("-r", "--reporting", help="Download reporting modules", action="store_true", required=False)
    parser.add_argument("-an", "--analyzer", help="Download analyzer modules/binaries/etc", action="store_true", required=False)
    parser.add_argument("-data", "--data", help="Download data things", action="store_true", required=False)
    parser.add_argument("-f", "--force", help="Install files without confirmation", action="store_true", default=False, required=False)
    parser.add_argument("-w", "--rewrite", help="Rewrite existing files", action="store_true", required=False)
    parser.add_argument("-b", "--branch", help="Specify a different branch", action="store", default="master", required=False)
    parser.add_argument("--file", help="Specify a local copy of a community .zip file", action="store", default=False, required=False)
    args = parser.parse_args()

    URL = URL.format(args.branch)

    if args.all:
        enabled = ["feeds", "processing", "signatures", "reporting", "machinery", "analyzer", "data"]
    else:
        if args.feeds:
            enabled.append("feeds")
        if args.signatures:
            enabled.append("signatures")
        if args.processing:
            enabled.append("processing")
        if args.reporting:
            enabled.append("reporting")
        if args.machinery:
            enabled.append("machinery")
        if args.analyzer:
            enabled.append("analyzer")
        if args.data:
            enabled.append("data")

    if not enabled:
        print(colors.red("You need to enable some category!\n"))
        parser.print_help()
        return

    install(enabled, args.force, args.rewrite, args.file)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
