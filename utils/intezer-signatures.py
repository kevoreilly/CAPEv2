#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import argparse
import os
import sys

if sys.version_info[:2] < (3, 6):
    sys.exit("You are running an incompatible version of Python, please use >= 3.6")
import logging
import tarfile
import requests
from io import BytesIO

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

import lib.cuckoo.common.colors as colors
from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger(__name__)
URL = "https://bitbucket.org/intezer/cape-signatures/get/master.tar.gz"


def download(user, password):
    print("Downloading signatures from {0}".format(URL))
    try:
        data = requests.get(URL, auth=(user, password), stream=True).raw.read()
        tar = tarfile.TarFile.open(fileobj=BytesIO(data), mode="r:gz")
    except Exception as e:
        print("ERROR: Unable to download archive: %s" % e)
        sys.exit(-1)

    members = tar.getmembers()
    directory = members[0].name.split("/")[0]
    name_start = "%s/%s" % (directory, 'signatures')

    for member in members:
        filepath = os.path.join(CUCKOO_ROOT, 'signatures', member.name[len(name_start) + 1:])

        if not member.name.startswith(name_start) or name_start == member.name:
            continue

        print('File "{}" {}'.format(filepath, colors.green("installed")))
        open(filepath, "wb").write(tar.extractfile(member).read())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--user", help="User name in bitbucket", type=str, required=True)
    parser.add_argument("-p", "--password", help="App password in bitbucket", type=str, required=True)
    args = parser.parse_args()

    download(args.user, args.password)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
