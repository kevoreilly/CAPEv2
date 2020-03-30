#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys

if sys.version_info[:2] < (3, 6):
    sys.exit("You are running an incompatible version of Python, please use >= 3.6")

import shutil
import urllib3
import argparse
import tempfile
from zipfile import ZipFile
from io import BytesIO

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

import lib.cuckoo.common.colors as colors
from lib.cuckoo.common.constants import CUCKOO_ROOT

URL = "https://github.com/kevoreilly/community/archive/{0}.zip"

def download_archive(filepath):
    if filepath and os.path.exists(filepath):
        data = open(filepath, "rb").read()
    else:
        print("Downloading modules from {0}".format(URL))
        try:
            http = urllib3.PoolManager()
            data = http.request('GET', URL).data
        except Exception as e:
            print("ERROR: Unable to download archive: %s" % e)
            sys.exit(-1)

    zip_data = BytesIO()
    zip_data.write(data)
    archive = ZipFile(zip_data, "r")
    temp_dir = tempfile.mkdtemp()
    archive.extractall(temp_dir)
    archive.close()
    final_dir = os.path.join(temp_dir, os.listdir(temp_dir)[0])

    return temp_dir, final_dir


def install(enabled, force, rewrite, filepath):
    (temp, source) = download_archive(filepath)

    folders = {
        "feeds": os.path.join("modules", "feeds"),
        "signatures": os.path.join("modules", "signatures"),
        "processing": os.path.join("modules", "processing"),
        "reporting": os.path.join("modules", "reporting"),
        "machinery": os.path.join("modules", "machinery")
    }

    for category in enabled:
        folder = folders.get(category, False)
        if not folder:
            continue
        print("\nInstalling {0}".format(colors.cyan(category.upper())))

        origin = os.path.join(source, folder)

        for file_name in os.listdir(origin):
            if file_name == ".gitignore":
                continue

            destination = os.path.join(CUCKOO_ROOT, folder, file_name)

            if not rewrite:
                if os.path.exists(destination):
                    print("File \"{0}\" already exists, "
                          "{1}".format(file_name, colors.yellow("skipped")))
                    continue

            install = False

            if not force:
                while 1:
                    choice = input("Do you want to install file "
                                       "\"{0}\"? [yes/no] ".format(file_name))
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
                shutil.copy(os.path.join(origin, file_name), destination)
                print("File \"{0}\" {1}".format(file_name,
                                                colors.green("installed")))

    shutil.rmtree(temp)

def main():
    global URL

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--all", help="Download everything", action="store_true", required=False)
    parser.add_argument("-e", "--feeds", help="Download CAPE feed modules", action="store_true", required=False)
    parser.add_argument("-s", "--signatures", help="Download CAPE signatures", action="store_true", required=False)
    parser.add_argument("-p", "--processing", help="Download processing modules", action="store_true", required=False)
    parser.add_argument("-m", "--machinery", help="Download machine managers",action="store_true", required=False)
    parser.add_argument("-r", "--reporting", help="Download reporting modules", action="store_true", required=False)
    parser.add_argument("-f", "--force", help="Install files without confirmation", action="store_true", required=False)
    parser.add_argument("-w", "--rewrite", help="Rewrite existing files", action="store_true", required=False)
    parser.add_argument("-b", "--branch", help="Specify a different branch", action="store", default="master", required=False)
    parser.add_argument("--file", help="Specify a local copy of a community .zip file", action="store", default=False, required=False)
    args = parser.parse_args()

    enabled = []
    force = True if args.force else False
    rewrite = True if args.rewrite else False

    if args.all:
        enabled = ["feeds", "processing", "signatures", "reporting", "machinery"]
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

    if not enabled:
        print(colors.red("You need to enable some category!\n"))
        parser.print_help()
        return

    URL = URL.format(args.branch)

    install(enabled, force, rewrite, args.file)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
