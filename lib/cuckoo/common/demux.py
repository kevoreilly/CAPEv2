# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import tempfile
import logging

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.exceptions import CuckooDemuxError
from lib.cuckoo.common.utils import get_options


sf_version = ""
try:
    from sflock import unpack, __version__ as sf_version
    from sflock.unpack.office import OfficeFile
    from sflock.abstracts import File as sfFile
    from sflock.exception import UnpackException

    HAS_SFLOCK = True
except ImportError:
    print("You must install sflock\n" "sudo apt-get install p7zip-full lzip rar unace-nonfree cabextract\n" "pip3 install -U SFlock2")
    HAS_SFLOCK = False

if sf_version:
    sf_version_splited = sf_version.split(".")
    # Before 14 there is core changes that required by CAPE, since exit
    if int(sf_version_splited[-1]) < 14:
        print("You using old version of sflock! Upgrade: pip3 install -U SFlock2")
        sys.exit()
    # Latest release
    if int(sf_version_splited[-1]) < 27:
        print("You using old version of sflock! Upgrade: pip3 install -U SFlock2")

log = logging.getLogger(__name__)
cuckoo_conf = Config()
tmp_path = cuckoo_conf.cuckoo.get("tmppath", "/tmp").encode("utf8")

demux_extensions_list = [
    "",
    b".exe",
    b".dll",
    b".com",
    b".jar",
    b".pdf",
    b".msi",
    b".bin",
    b".scr",
    b".zip",
    b".tar",
    b".gz",
    b".tgz",
    b".rar",
    b".htm",
    b".html",
    b".hta",
    b".doc",
    b".dot",
    b".docx",
    b".dotx",
    b".docm",
    b".dotm",
    b".docb",
    b".mht",
    b".mso",
    b".js",
    b".jse",
    b".vbs",
    b".vbe",
    b".xls",
    b".xlt",
    b".xlm",
    b".xlsx",
    b".xltx",
    b".xlsm",
    b".xltm",
    b".xlsb",
    b".xla",
    b".xlam",
    b".xll",
    b".xlw",
    b".ppt",
    b".pot",
    b".pps",
    b".pptx",
    b".pptm",
    b".potx",
    b".potm",
    b".ppam",
    b".ppsx",
    b".ppsm",
    b".sldx",
    b".sldm",
    b".wsf",
    b".bat",
    b".ps1",
    b".sh",
    b".pl",
    b".lnk",
]

whitelist_extensions = ("doc", "xls", "ppt", "pub", "jar")

blacklist_extensions = ("apk", "dmg")

# list of valid file types to extract - TODO: add more types
VALID_TYPES = ["PE32", "Java Jar", "Outlook", "Message", "MS Windows shortcut"]
VALID_LINUX_TYPES = ["Bourne-Again", "POSIX shell script", "ELF", "Python"]


def options2passwd(options):
    password = False
    if "password=" in options:
        password = get_options(options).get("password")
        if password and isinstance(password, bytes):
            password = password.decode("utf8")

    return password


def demux_office(filename, password):
    retlist = []
    basename = os.path.basename(filename)
    target_path = os.path.join(tmp_path, b"cuckoo-tmp/msoffice-crypt-tmp")
    if not os.path.exists(target_path):
        os.makedirs(target_path)
    decrypted_name = os.path.join(target_path, basename)

    if HAS_SFLOCK:
        ofile = OfficeFile(sfFile.from_path(filename))
        d = ofile.decrypt(password)
        if hasattr(d, "contents"):
            with open(decrypted_name, "w") as outs:
                outs.write(d.contents)
            # TODO add decryption verification checks
            if "Encrypted" not in d.magic:
                retlist.append(decrypted_name)
    else:
        raise CuckooDemuxError("MS Office decryptor not available")

    if not retlist:
        retlist.append(filename)

    return retlist


def is_valid_type(magic):
    # check for valid file types and don't rely just on file extentsion
    VALID_TYPES.extend(VALID_LINUX_TYPES)
    for ftype in VALID_TYPES:
        if ftype in magic:
            return True
    return False


def _sf_chlildren(child):
    path_to_extract = False
    _, ext = os.path.splitext(child.filename)
    ext = ext.lower()
    if ext in demux_extensions_list or is_valid_type(child.magic):
        target_path = os.path.join(tmp_path, b"cuckoo-sflock")
        if not os.path.exists(target_path):
            os.mkdir(target_path)
        tmp_dir = tempfile.mkdtemp(dir=target_path)
        try:
            if child.contents:
                path_to_extract = os.path.join(tmp_dir, child.filename)
                with open(path_to_extract, "wb") as f:
                    f.write(child.contents)
        except Exception as e:
            log.error(e, exc_info=True)
    return path_to_extract


def demux_sflock(filename, options, package):
    retlist = []
    # only extract from files with no extension or with .bin (downloaded from us) or .zip PACKAGE, we do extract from zip archives, to ignore it set ZIP PACKAGES
    ext = os.path.splitext(filename)[1]
    if ext == b".bin":
        return retlist

    # to handle when side file for exec is required
    if "file=" in options:
        return [filename]

    try:
        password = "infected"
        tmp_pass = options2passwd(options)
        if tmp_pass:
            password = tmp_pass

        try:
            unpacked = unpack(filename, password=password)
        except UnpackException:
            unpacked = unpack(filename)

        if unpacked.package in whitelist_extensions:
            return [filename]
        if unpacked.package in blacklist_extensions:
            return retlist
        for sf_child in unpacked.children or []:
            if sf_child.to_dict().get("children") and sf_child.to_dict()["children"]:
                retlist += [_sf_chlildren(ch) for ch in sf_child.to_dict()["children"]]
            else:
                retlist.append(_sf_chlildren(sf_child))
    except Exception as e:
        log.error(e, exc_info=True)

    return list(filter(None, retlist))


def demux_sample(filename, package, options, use_sflock=True):
    """
    If file is a ZIP, extract its included files and return their file paths
    If file is an email, extracts its attachments and return their file paths (later we'll also extract URLs)
    """
    # sflock requires filename to be bytes object for Py3
    if isinstance(filename, str) and use_sflock:
        filename = filename.encode("utf8")
    # if a package was specified, then don't do anything special
    if package:
        return [filename]

    # don't try to extract from office docs
    magic = File(filename).get_type()

    # if file is an Office doc and password is supplied, try to decrypt the doc
    if "Microsoft" in magic:
        ignore = ["Outlook", "Message", "Disk Image"]
        if any(x in magic for x in ignore):
            pass
        elif "Composite Document File" in magic or "CDFV2 Encrypted" in magic:
            password = False
            tmp_pass = options2passwd(options)
            if tmp_pass:
                password = tmp_pass

    # don't try to extract from Java archives or executables
    if "Java Jar" in magic:
        return [filename]
    if "PE32" in magic or "MS-DOS executable" in magic:
        return [filename]
    if any(x in magic for x in VALID_LINUX_TYPES):
        return [filename]

    retlist = list()
    if HAS_SFLOCK:
        if use_sflock:
            # all in one unarchiver
            retlist = demux_sflock(filename, options, package)
    # if it wasn't a ZIP or an email or we weren't able to obtain anything interesting from either, then just submit the
    # original file
    if not retlist:
        retlist.append(filename)
    else:
        if len(retlist) > 10:
            retlist = retlist[:10]

    return retlist
