#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import logging

try:
    import yara

    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

log = logging.getLogger()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.objects import File
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT


def init_yara():
    """Generates index for yara signatures."""

    def find_signatures(root):
        signatures = []
        for entry in os.listdir(root):
            if entry.endswith(".yara") or entry.endswith(".yar"):
                signatures.append(os.path.join(root, entry))

        return signatures

    print("Initializing Yara...")

    # Generate root directory for yara rules.
    yara_root = os.path.join(CUCKOO_ROOT, "data", "yara")

    # We divide yara rules in three categories.
    # CAPE adds a fourth
    categories = ["binaries", "memory", "CAPE"]  # "urls"
    generated = []
    # Loop through all categories.
    for category in categories:
        # Check if there is a directory for the given category.
        category_root = os.path.join(yara_root, category)
        if not os.path.exists(category_root):
            continue

        # Check if the directory contains any rules.
        signatures = []
        for entry in os.listdir(category_root):
            if entry.endswith(".yara") or entry.endswith(".yar"):
                signatures.append(os.path.join(category_root, entry))
                try:
                    compile_yara(os.path.join(category_root, entry))
                except Exception as e:
                    print(os.path.join(category_root, entry), e)

        if not signatures:
            continue

        # Generate path for the category's index file.
        index_name = "index_{0}.yar".format(category)
        index_path = os.path.join(yara_root, index_name)

        # Create index file and populate it.
        with open(index_path, "w") as index_handle:
            for signature in signatures:
                index_handle.write('include "{0}"\n'.format(signature))

        generated.append(index_name)

    for entry in generated:
        if entry == generated[-1]:
            print(("\t `-- {}", entry))
        else:
            print(("\t |-- {}", entry))


def compile_yara(rulepath=""):
    """Compile Yara signatures.
    """
    if not HAVE_YARA:
        if not File.notified_yara:
            File.notified_yara = True
            print("Unable to import yara (please compile from sources)")
        return

    if not os.path.exists(rulepath):
        print(("The specified rule file at {} doesn't exist, skip", rulepath))
        return

    try:
        rules = yara.compile(rulepath)
    except Exception as e:
        print("Unexpected error:", sys.exc_info()[0])
        raise
        if "duplicated identifier" in e.args[0]:
            print("Duplicate rule in {}, rulepath")
            print(e.args[0])
        else:
            print("ERROR: SyntaxError in rules: {}".format(e.args))
            return


def test_yara():
    print("About to attempt to compile yara rules...")

    # Generate root directory for yara rules.
    yara_root = os.path.join(CUCKOO_ROOT, "data", "yara")

    # We divide yara rules in three categories.
    # CAPE adds a fourth
    categories = ["binaries", "urls", "memory", "CAPE"]
    generated = []
    # Loop through all categories.
    for category in categories:
        # Check if there is a directory for the given category.
        category_root = os.path.join(yara_root, category)
        if not os.path.exists(category_root):
            continue

        # Generate path for the category's index file.
        index_name = "index_{0}.yar".format(category)
        index_path = os.path.join(yara_root, index_name)

        print(("Compiling {}", format(index_path)))
        compile_yara(index_path)


def main():
    os.chdir(CUCKOO_ROOT)

    init_yara()
    test_yara()

    print("Complete")


if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
