from __future__ import absolute_import, print_function
import argparse
import base64
import os
import zipfile


# ----------------------------------------------------------------
# extract_config : This extracts the C&C information from Ratty.
# https://github.com/Sogomn/Ratty
# ----------------------------------------------------------------
def extract_config(zip):
    c2 = []
    bFile = False
    fh = open(zip, "rb")
    z = zipfile.ZipFile(fh)
    for name in z.namelist():
        if name == "data":
            bFile = True
            data = z.read(name)
            try:
                data = base64.b64decode(data)
                for i in range(len(data)):
                    c2.append(chr(ord(data[i]) ^ 0x38))

                print(f"[+] Found it : {zip}")
                print(f"[+] C2 : {''.join(c2)}")
            except Exception:
                print("[*] Probably corrupted Base64 string")
    if bFile == False:
        print("[*] No such file")
    print("[+] Task Completed\n")
    fh.close()


# -------------------------------------------------------------
# check_jar_classes : Shitty Check whether file is a jar file.
# -------------------------------------------------------------
def check_jar_classes(jar_file):
    bJar = False
    try:
        zf = zipfile.ZipFile(jar_file, "r")
        lst = zf.infolist()
        for zi in lst:
            fn = zi.filename
            if fn.endswith(".class"):
                bJar = True
                return bJar
    except Exception:
        return False


# -------------------------------------------------------------
# logo : Ascii Logos like the 90s. :P
# -------------------------------------------------------------
def logo():
    print("\n")
    print(" ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __   ")
    print('/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \  ')
    print('\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \ ')
    print(
        ' \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\\\"\_\\'
    )
    print("  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/")
    print("\n")
    print(" Find the C&C for this Ratty mallie!")
    print(" Jacob Soo")
    print(" Copyright (c) 2016\n")


if __name__ == "__main__":
    description = "C&C Extraction tool for Ratty (https://github.com/Sogomn/Ratty)."
    parser = argparse.ArgumentParser(description=description, epilog="--file and --directory are mutually exclusive")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", action="store", nargs=1, dest="szFilename", help="filename", metavar="filename")
    group.add_argument(
        "-d", "--directory", action="store", nargs=1, dest="szDirectory", help="Location of directory.", metavar="directory"
    )

    args = parser.parse_args()
    Filename = args.szFilename
    Directory = args.szDirectory
    try:
        is_file = os.path.isfile(Filename[0])
    except Exception:
        pass
    try:
        is_dir = os.path.isdir(Directory[0])
    except Exception:
        pass
    logo()
    if Filename is not None and is_file:
        extract_config(Filename[0])
    else:
        print("You probably have supplied a invalid file")
    if Directory is not None and is_dir:
        for root, directories, filenames in os.walk(Directory[0]):
            for filename in filenames:
                szFile = os.path.join(root, filename)
                if check_jar_classes(szFile) == True:
                    extract_config(szFile)
                else:
                    print(f"This is not a valid Jar file : {szFile}")
