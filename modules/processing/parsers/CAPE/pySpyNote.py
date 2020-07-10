#!/usr/bin/python
from __future__ import absolute_import
from __future__ import print_function
import zipfile, sys, os
import base64, urllib.request, urllib.parse, urllib.error
import argparse
from sys import argv
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm

# ---------------------------------------------------
# _log : Prints out logs for debug purposes
# ---------------------------------------------------
def _log(s):
    print(s)


# ------------------------------------------------------------------
# extract_config : This extracts the C&C information from SpyNote.
# ------------------------------------------------------------------
def extract_config(apkfile):
    a = apk.APK(apkfile)
    d = dvm.DalvikVMFormat(a.get_dex())
    for cls in d.get_classes():
        if "dell/scream/application/MainActivity;".lower() in cls.get_name().lower():
            c2 = ""
            port = ""
            string = None
            for method in cls.get_methods():
                if method.name == "<init>":
                    for inst in method.get_instructions():
                        if inst.get_name() == "const-string":
                            string = inst.get_output().split(",")[-1].strip(" '")
                        if inst.get_name() == "iput-object":
                            if "SERVER_IP" in inst.get_output():
                                c2 = string
                            if "PORT" in inst.get_output():
                                port = string
                        if c2 and port:
                            break
            server = ""
            if port:
                server = "{0}:{1}".format(c2, str(port))
            else:
                server = c2
            _log("Extracting from %s" % apkfile)
            _log("C&C: [ %s ]\n" % server)


# -------------------------------------------------------------
# check_apk_file : Shitty Check whether file is a apk file.
# -------------------------------------------------------------
def check_apk_file(apk_file):
    bJar = False
    try:
        zf = zipfile.ZipFile(apk_file, "r")
        lst = zf.infolist()
        for zi in lst:
            fn = zi.filename
            if fn.lower() == "androidmanifest.xml":
                bJar = True
                return bJar
    except:
        return bJar


# -------------------------------------------------------------
# logo : Ascii Logos like the 90s. :P
# -------------------------------------------------------------
def logo():
    print("\n")
    print(" ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __   ")
    print('/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \  ')
    print('\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \ ')
    print(' \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\\\"\_\\')
    print("  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/")
    print("\n")
    print(" Find the C&C for this Spynote mallie!")
    print(" Jacob Soo")
    print(" Copyright (c) 2016\n")


if __name__ == "__main__":
    description = "C&C Extraction tool for Spynote"
    parser = argparse.ArgumentParser(description=description, epilog="--file and --directory are mutually exclusive")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", action="store", nargs=1, dest="szFilename", help="filename", metavar="filename")
    group.add_argument("-d", "--directory", action="store", nargs=1, dest="szDirectory", help="Location of directory.", metavar="directory")

    args = parser.parse_args()
    Filename = args.szFilename
    Directory = args.szDirectory
    is_file = False
    is_dir = False
    try:
        is_file = os.path.isfile(Filename[0])
    except:
        pass
    try:
        is_dir = os.path.isdir(Directory[0])
    except:
        pass
    logo()
    if Filename is not None and is_file:
        if check_apk_file(Filename[0]) == True:
            extract_config(Filename[0])
        else:
            print(("This is not a valid apk file : %s" % Filename[0]))
    if Directory is not None and is_dir:
        for root, directories, filenames in os.walk(Directory[0]):
            for filename in filenames:
                szFile = os.path.join(root, filename)
                if check_apk_file(szFile) == True:
                    extract_config(szFile)
                else:
                    print(("This is not a valid apk file : %s" % szFile))
