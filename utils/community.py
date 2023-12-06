#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import shutil
import sys
import zipfile
from contextlib import suppress

if sys.version_info[:2] < (3, 8):
    sys.exit("You are running an incompatible version of Python, please use >= 3.8")

import argparse
import logging
import tarfile
from io import BytesIO

import urllib3

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

import lib.cuckoo.common.colors as colors
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.integrations.mitre import mitre_update
from lib.cuckoo.common.path_utils import path_exists, path_mkdir

blocklist = {}
if path_exists(os.path.join(CUCKOO_ROOT, "utils", "community_blocklist.py")):
    from utils.community_blocklist import blocklist

log = logging.getLogger(__name__)


def flare_capa(proxy=None):
    signature_urls = (
        "https://github.com/mandiant/capa/raw/master/sigs/1_flare_msvc_rtf_32_64.sig",
        "https://github.com/mandiant/capa/raw/master/sigs/2_flare_msvc_atlmfc_32_64.sig",
        "https://github.com/mandiant/capa/raw/master/sigs/3_flare_common_libs.sig",
    )
    try:
        if proxy:
            http = urllib3.ProxyManager(proxy)
        else:
            http = urllib3.PoolManager()
        data = http.request("GET", "https://github.com/mandiant/capa-rules/archive/master.zip").data
        dest_folder = os.path.join(CUCKOO_ROOT, "data")
        shutil.rmtree((os.path.join(dest_folder, "capa-rules-master")), ignore_errors=True)
        shutil.rmtree((os.path.join(dest_folder, "capa-rules")), ignore_errors=True)
        zipfile.ZipFile(BytesIO(data)).extractall(path=dest_folder)
        os.rename(os.path.join(dest_folder, "capa-rules-master"), os.path.join(dest_folder, "capa-rules"))

        # shutil.rmtree((os.path.join(dest_folder, "capa-signatures")), ignore_errors=True)
        capa_sigs_path = os.path.join(dest_folder, "flare-signatures")
        if not os.path.isdir(capa_sigs_path):
            path_mkdir(capa_sigs_path)
        for url in signature_urls:
            signature_name = url.rsplit("/", 1)[-1]
            with http.request("GET", url, preload_content=False) as sig, open(
                os.path.join(capa_sigs_path, signature_name), "wb"
            ) as out_sig:
                shutil.copyfileobj(sig, out_sig)

        print("[+] FLARE CAPA rules/signatures installed")
    except Exception as e:
        print(e)


def install(enabled, force, rewrite, filepath: str = False, access_token=None, proxy=False, url: str = False):
    if filepath and path_exists(filepath):
        t = tarfile.TarFile.open(filepath, mode="r:gz")
    else:
        print(f"Downloading modules from {url}")
        try:
            if proxy:
                http = urllib3.ProxyManager(proxy)
            else:
                http = urllib3.PoolManager()
            if access_token is None:
                data = http.request("GET", url).data
            elif "github" in url:
                data = http.request(
                    "GET", url, headers={"Authorization": f"token {access_token}", "User-Agent": "CAPEv2_sandbox"}
                ).data
            else:
                data = http.request("GET", url, headers={"PRIVATE-TOKEN": access_token}).data

            if b"Not Found" == data:
                print("You don't have permissions to access this repo")
                sys.exit(-1)
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
        "common": "lib/cuckoo/common",
        "integrations": "lib/cuckoo/common/integrations",
        "mitre": "data/mitre",
        "yara": "data/yara",
        "utils": "utils",
    }

    members = t.getmembers()
    directory = members[0].name.split("/", 1)[0]

    for category in enabled:
        folder = folders.get(category, False)
        if not folder:
            continue

        print(f"\nInstalling {colors.cyan(category.upper())}")

        # E.g., "community-master/modules/signatures".
        name_start = f"{directory}/{folder}"
        for member in members:
            if not member.name.startswith(name_start) or name_start == member.name:
                continue

            filepath = os.path.join(CUCKOO_ROOT, folder, member.name[len(name_start) + 1 :])
            if member.name.lower().endswith((".gitignore", "readme.md", "-ci.yml")):
                continue

            if member.isdir():
                if not path_exists(filepath):
                    path_mkdir(filepath)
                continue

            if not rewrite and path_exists(filepath):
                print(f'File "{filepath}" already exists, {colors.yellow("skipped")}')
                continue

            install = False
            dest_file = os.path.basename(filepath)

            if filepath in blocklist.get(category, []):
                print(f'You have blocklisted file: {dest_file}. {colors.yellow("skipped")}')
                continue

            if not force:
                while True:
                    choice = input(f'Do you want to install file "{dest_file}"? [yes/no] ')
                    if choice.lower() in ("y", "yes"):
                        install = True
                        break
                    elif choice.lower() in ("n", "no"):
                        break
            else:
                install = True

            if install:
                if not path_exists(os.path.dirname(filepath)):
                    path_mkdir(os.path.dirname(filepath))

                try:
                    with open(filepath, "wb") as f:
                        f.write(t.extractfile(member).read())
                    print(f'File "{filepath}" {colors.green("installed")}')
                except PermissionError:
                    print(colors.red(f"Fix permission on: {filepath}"))


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--all", help="Download everything", action="store_true", required=False)
    parser.add_argument("-cm", "--common", help="Download CAPE common modules", action="store_true", required=False)
    parser.add_argument("-e", "--feeds", help="Download CAPE feed modules", action="store_true", required=False)
    parser.add_argument("-s", "--signatures", help="Download CAPE signatures", action="store_true", required=False)
    parser.add_argument("-p", "--processing", help="Download processing modules", action="store_true", required=False)
    parser.add_argument("-m", "--machinery", help="Download machine managers", action="store_true", required=False)
    parser.add_argument("-r", "--reporting", help="Download reporting modules", action="store_true", required=False)
    parser.add_argument("-an", "--analyzer", help="Download analyzer modules/binaries/etc", action="store_true", required=False)
    parser.add_argument("-data", "--data", help="Download data items", action="store_true", required=False)
    parser.add_argument("-i", "--integrations", help="Download integration items", action="store_true", required=False)
    parser.add_argument(
        "-f", "--force", help="Install files without confirmation", action="store_true", default=False, required=False
    )
    parser.add_argument("-w", "--rewrite", help="Rewrite existing files", action="store_true", required=False)
    parser.add_argument("-b", "--branch", help="Specify a different branch", action="store", default="master", required=False)
    parser.add_argument(
        "--file", help="Specify a local copy of a community .zip file", action="store", default=False, required=False
    )
    parser.add_argument(
        "-cr", "--capa-rules", help="Download capa rules and signatures", action="store_true", default=False, required=False
    )
    parser.add_argument("--mitre", help="Download updated MITRE JSONS", action="store_true", default=False, required=False)
    parser.add_argument(
        "--mitre-offline",
        help="Download updated MITRE JSONS from community repo",
        action="store_true",
        default=False,
        required=False,
    )
    parser.add_argument(
        "-u", "--url", help="Download community modules from the specified url", action="store", default=None, required=False
    )
    parser.add_argument(
        "-t", "--token", help="Access token to download private repositories", action="store", default=None, required=False
    )
    parser.add_argument("--proxy", help="Proxy to use. Ex http://127.0.0.1:8080", action="store", required=False)
    parser.add_argument("-y", "--yara", help="Download YARA rules", action="store_true", required=False)
    args = parser.parse_args()

    enabled = []

    if args.all:
        enabled = [
            "feeds",
            "processing",
            "signatures",
            "reporting",
            "machinery",
            "analyzer",
            "data",
            "integrations",
            "mitre",
            "common",
        ]
        flare_capa(args.proxy)
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
        if args.common:
            enabled.append("common")
        # Data contains yara
        if args.data:
            enabled.append("data")
        elif args.yara:
            enabled.append("yara")
        if args.integrations:
            enabled.append("integrations")
        if args.mitre_offline:
            enabled.append("mitre")

    if args.capa_rules:
        flare_capa(args.proxy)
        if not enabled:
            return

    if args.mitre:
        mitre_update()
        if not enabled:
            return

    if not enabled:
        print(colors.red("You need to enable a category!\n"))
        parser.print_help()
        return

    install(
        enabled,
        args.force,
        args.rewrite,
        args.file,
        args.token,
        args.proxy,
        args.url or f"https://github.com/kevoreilly/community/archive/{args.branch}.tar.gz",
    )


if __name__ == "__main__":
    with suppress(KeyboardInterrupt):
        main()
