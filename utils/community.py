#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shutil
import os
import sys
import zipfile
from io import BytesIO
if sys.version_info[:2] < (3, 6):
    sys.exit("You are running an incompatible version of Python, please use >= 3.6")
import logging
import urllib3
import argparse
import tarfile
from io import BytesIO

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

import lib.cuckoo.common.colors as colors
from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger(__name__)
URL = "https://github.com/kevoreilly/community/archive/{0}.tar.gz"

def flare_capa():
    signature_urls = (
        'https://github.com/mandiant/capa/raw/master/sigs/1_flare_msvc_rtf_32_64.sig',
        'https://github.com/mandiant/capa/raw/master/sigs/2_flare_msvc_atlmfc_32_64.sig',
        'https://github.com/mandiant/capa/raw/master/sigs/3_flare_common_libs.sig',
    )
    try:
        http = urllib3.PoolManager()
        data = http.request("GET", "https://github.com/mandiant/capa-rules/archive/master.zip").data
        dest_folder = os.path.join(CUCKOO_ROOT, "data")
        shutil.rmtree((os.path.join(dest_folder, "capa-rules-master")), ignore_errors=True)
        shutil.rmtree((os.path.join(dest_folder, "capa-rules")), ignore_errors=True)
        zipfile.ZipFile(BytesIO(data)).extractall(path=dest_folder)
        os.rename(os.path.join(dest_folder, "capa-rules-master"), os.path.join(dest_folder, "capa-rules"))

        # shutil.rmtree((os.path.join(dest_folder, "capa-signatures")), ignore_errors=True)
        capa_sigs_path = os.path.join(dest_folder, "capa-signatures")
        if not os.path.isdir(capa_sigs_path):
            os.mkdir(capa_sigs_path)
        for url in signature_urls:
            signature_name = url.split('/')[-1]
            with http.request("GET", url, preload_content=False) as sig, open(os.path.join(capa_sigs_path, signature_name), 'wb') as out_sig:
                shutil.copyfileobj(sig, out_sig)

        print("[+] FLARE CAPA rules/signatures installed")
    except Exception as e:
        print(e)

def mitre():
    """ Urls might change, for proper urls see https://github.com/swimlane/pyattck"""
    try:
        from pyattck import Attck
    except ImportError:
        print("Missed dependency: install pyattck library, see requirements for proper version")
        return

    mitre = Attck(
        nested_subtechniques=True,
        save_config=False,
        use_config=False,
        config_file_path=os.path.join(CUCKOO_ROOT, "data", "mitre", "config.yml"),
        data_path=os.path.join(CUCKOO_ROOT, "data", "mitre"),
        enterprise_attck_json="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        pre_attck_json="https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json",
        mobile_attck_json="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        nist_controls_json="https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/master/frameworks/ATT%26CK-v9.0/nist800-53-r4/stix/nist800-53-r4-controls.json",
        generated_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/generated_attck_data.json",
        generated_nist_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json",
     )

    print("[+] Updating MITRE datasets")
    mitre.update()

def install(enabled, force, rewrite, filepath):
    if filepath and os.path.exists(filepath):
        data = open(filepath, "rb").read()
    else:
        print("Downloading modules from {0}".format(URL))
        try:
            http = urllib3.PoolManager()
            data = http.request("GET", URL).data
            t = tarfile.TarFile.open(fileobj=BytesIO(data), mode="r:gz")
        except Exception as e:
            print("ERROR: Unable to download archive: %s" % e)
            sys.exit(-1)

    folders = {
        "feeds": "modules/feeds",
        "signatures": "modules/signatures",
        "processing": "modules/processing",
        "reporting": "modules/reporting",
        "machinery": "modules/machinery",
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

        # E.g., "community-master/modules/signatures".
        name_start = "%s/%s" % (directory, folder)
        for member in members:
            if not member.name.startswith(name_start) or name_start == member.name:
                continue

            filepath = os.path.join(CUCKOO_ROOT, folder, member.name[len(name_start) + 1 :])
            if member.name.endswith(".gitignore"):
                continue

            if member.isdir():
                if not os.path.exists(filepath):
                    os.mkdir(filepath)
                continue

            if not rewrite:
                if os.path.exists(filepath):
                    print('File "{}" already exists, {}'.format(filepath, colors.yellow("skipped")))
                    continue

            install = False
            dest_file = os.path.basename(filepath)
            if not force:
                while 1:
                    choice = input('Do you want to install file "{}"? [yes/no] '.format(dest_file))
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

                print('File "{}" {}'.format(filepath, colors.green("installed")))
                open(filepath, "wb").write(t.extractfile(member).read())


def main():
    global URL

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--all", help="Download everything", action="store_true", required=False)
    parser.add_argument("-e", "--feeds", help="Download CAPE feed modules", action="store_true", required=False)
    parser.add_argument("-s", "--signatures", help="Download CAPE signatures", action="store_true", required=False)
    parser.add_argument("-p", "--processing", help="Download processing modules", action="store_true", required=False)
    parser.add_argument("-m", "--machinery", help="Download machine managers", action="store_true", required=False)
    parser.add_argument("-r", "--reporting", help="Download reporting modules", action="store_true", required=False)
    parser.add_argument("-an", "--analyzer", help="Download analyzer modules/binaries/etc", action="store_true", required=False)
    parser.add_argument("-data", "--data", help="Download data items", action="store_true", required=False)
    parser.add_argument("-f", "--force", help="Install files without confirmation", action="store_true", default=False, required=False)
    parser.add_argument("-w", "--rewrite", help="Rewrite existing files", action="store_true", required=False)
    parser.add_argument("-b", "--branch", help="Specify a different branch", action="store", default="master", required=False)
    parser.add_argument("--file", help="Specify a local copy of a community .zip file", action="store", default=False, required=False)
    parser.add_argument("-cr", "--capa-rules", help="Download capa rules and signatures", action="store_true", default=False, required=False)
    parser.add_argument("--mitre", help="Download updated MITRE JSONS", action="store_true", default=False, required=False)
    args = parser.parse_args()

    URL = URL.format(args.branch)
    enabled = []

    if args.all:
        enabled = ["feeds", "processing", "signatures", "reporting", "machinery", "analyzer", "data"]
        flare_capa()
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

    if args.capa_rules:
        flare_capa()
        if not enabled:
            return

    if args.mitre:
        mitre()
        if not enabled:
            return

    if not enabled:
        print(colors.red("You need to enable a category!\n"))
        parser.print_help()
        return

    install(enabled, args.force, args.rewrite, args.file)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass

