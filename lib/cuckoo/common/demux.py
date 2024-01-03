# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import tempfile
from typing import List

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooDemuxError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists, path_mkdir, path_write_file
from lib.cuckoo.common.quarantine import unquarantine
from lib.cuckoo.common.trim_utils import trim_file, trimmed_path
from lib.cuckoo.common.utils import get_options, get_platform, sanitize_filename

sfFile = False
sf_version = ""
try:
    from sflock import __version__ as sf_version
    from sflock import unpack
    from sflock.abstracts import File as sfFile
    from sflock.exception import UnpackException
    from sflock.unpack.office import OfficeFile

    HAS_SFLOCK = True
except ImportError:
    print("\n\n[!] Missde dependencies. Run: poetry install\n\n")
    HAS_SFLOCK = False

if sf_version and int(sf_version.split(".")[-1]) < 42:
    print("You using old version of sflock! Upgrade: poetry install")

log = logging.getLogger(__name__)
cuckoo_conf = Config()
web_cfg = Config("web")
tmp_path = cuckoo_conf.cuckoo.get("tmppath", "/tmp")
linux_enabled = web_cfg.linux.get("enabled", False)

demux_extensions_list = {
    b".accdr",
    b".exe",
    b".dll",
    b".com",
    b".jar",
    b".pdf",
    b".msi",
    b".msix",
    b".msixbundle",
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
    b".one",
    b".onetoc2",
}

whitelist_extensions = {"doc", "xls", "ppt", "pub", "jar"}

blacklist_extensions = {"apk", "dmg"}

# list of valid file types to extract - TODO: add more types
VALID_TYPES = {"PE32", "Java Jar", "Outlook", "Message", "MS Windows shortcut", "PDF document"}
VALID_LINUX_TYPES = {"Bourne-Again", "POSIX shell script", "ELF", "Python"}
VALID_PACKAGES = {"doc", "xls", "ppt", "pdf"}
OFFICE_TYPES = [
    "Composite Document File",
    "CDFV2 Encrypted",
    "Excel 2007+",
    "Word 2007+",
    "Microsoft OOXML",
]


def options2passwd(options: str) -> str:
    password = ""
    if "password=" in options:
        password = get_options(options).get("password")
        if password and isinstance(password, bytes):
            password = password.decode()

    return password


def demux_office(filename: bytes, password: str, platform: str) -> List[bytes]:
    retlist = []
    target_path = os.path.join(tmp_path, "cuckoo-tmp/msoffice-crypt-tmp")
    if not path_exists(target_path):
        path_mkdir(target_path)
    decrypted_name = os.path.join(target_path, os.path.basename(filename).decode())

    if HAS_SFLOCK:
        ofile = OfficeFile(sfFile.from_path(filename))
        d = ofile.decrypt(password)
        # TODO: add decryption verification checks
        if hasattr(d, "contents") and "Encrypted" not in d.magic:
            _ = path_write_file(decrypted_name, d.contents)
            retlist.append((decrypted_name.encode(), platform))
    else:
        raise CuckooDemuxError("MS Office decryptor not available")

    if not retlist:
        retlist.append((filename, platform))

    return retlist


def is_valid_type(magic: str) -> bool:
    # check for valid file types and don't rely just on file extension
    VALID_TYPES.update(VALID_LINUX_TYPES)
    return any(ftype in magic for ftype in VALID_TYPES)


def is_valid_package(package: str) -> bool:
    # check if the file has a valid package type
    if not package:
        return False
    return any(ptype in package for ptype in VALID_PACKAGES)


def _sf_children(child: sfFile) -> bytes:
    path_to_extract = ""
    _, ext = os.path.splitext(child.filename)
    ext = ext.lower()
    if (
        ext in demux_extensions_list
        or is_valid_package(child.package)
        or is_valid_type(child.magic)
        or (not ext and is_valid_type(child.magic))
        # msix
        or all([pattern in child.contents for pattern in (b"Registry.dat", b"AppxManifest.xml")])
    ):
        target_path = os.path.join(tmp_path, "cuckoo-sflock")
        if not path_exists(target_path):
            path_mkdir(target_path)
        tmp_dir = tempfile.mkdtemp(dir=target_path)
        try:
            if child.contents:
                path_to_extract = os.path.join(tmp_dir, sanitize_filename((child.filename).decode()))
                _ = path_write_file(path_to_extract, child.contents)
        except Exception as e:
            log.error(e, exc_info=True)
    return path_to_extract.encode()


def demux_sflock(filename: bytes, options: str) -> List[bytes]:
    retlist = []
    # do not extract from .bin (downloaded from us)
    if os.path.splitext(filename)[1] == b".bin":
        return retlist

    try:
        password = options2passwd(options) or "infected"
        try:
            unpacked = unpack(filename, password=password, check_shellcode=True)
        except UnpackException:
            unpacked = unpack(filename, check_shellcode=True)

        if unpacked.package in whitelist_extensions:
            return [filename]
        if unpacked.package in blacklist_extensions:
            return [retlist]
        for sf_child in unpacked.children:
            if sf_child.to_dict().get("children"):
                retlist.extend(_sf_children(ch) for ch in sf_child.children)
                # child is not available, the original file should be put into the list
                if filter(None, retlist):
                    retlist.append(_sf_children(sf_child))
            else:
                retlist.append(_sf_children(sf_child))
    except Exception as e:
        log.error(e, exc_info=True)
    return list(filter(None, retlist))


def demux_sample(filename: bytes, package: str, options: str, use_sflock: bool = True, platform: str = ""):  # -> tuple[bytes, str]:
    """
    If file is a ZIP, extract its included files and return their file paths
    If file is an email, extracts its attachments and return their file paths (later we'll also extract URLs)
    """
    # sflock requires filename to be bytes object for Py3
    # TODO: Remove after checking all uses of demux_sample use bytes ~TheMythologist
    if isinstance(filename, str) and use_sflock:
        filename = filename.encode()

    retlist = []
    # if a package was specified, trim if allowed and required
    if package:

        if package in ("msix",):
            retlist.append((filename, "windows"))
        else:
            if File(filename).get_size() <= web_cfg.general.max_sample_size or (
                web_cfg.general.allow_ignore_size and "ignore_size_check" in options
            ):
                retlist.append((filename, platform))
            else:
                if web_cfg.general.enable_trim and trim_file(filename):
                    retlist.append((trimmed_path(filename), platform))
        return retlist

    # handle quarantine files
    tmp_path = unquarantine(filename)
    if tmp_path:
        filename = tmp_path

    # don't try to extract from office docs
    magic = File(filename).get_type()
    # if file is an Office doc and password is supplied, try to decrypt the doc
    if "Microsoft" in magic:
        pass
        # ignore = {"Outlook", "Message", "Disk Image"}
    elif any(x in magic for x in OFFICE_TYPES):
        password = options2passwd(options) or None
        if use_sflock:
            if HAS_SFLOCK:
                retlist = demux_office(filename, password, platform)
                return retlist
            else:
                log.error("Detected password protected office file, but no sflock is installed: poetry install")

    # don't try to extract from Java archives or executables
    if (
        "Java Jar" in magic
        or "Java archive data" in magic
        or "PE32" in magic
        or "MS-DOS executable" in magic
        or any(x in magic for x in VALID_LINUX_TYPES)
    ):
        retlist = []
        if File(filename).get_size() <= web_cfg.general.max_sample_size or (
            web_cfg.general.allow_ignore_size and "ignore_size_check" in options
        ):
            retlist.append((filename, platform))
        else:
            if web_cfg.general.enable_trim and trim_file(filename):
                retlist.append((trimmed_path(filename), platform))
        return retlist

    new_retlist = []
    # all in one unarchiver
    retlist = demux_sflock(filename, options) if HAS_SFLOCK and use_sflock else []
    # if it isn't a ZIP or an email, or we aren't able to obtain anything interesting from either, then just submit the
    # original file
    if not retlist:
        new_retlist.append((filename, platform))
    else:
        for filename in retlist:
            # verify not Windows binaries here:
            magic_type = File(filename).get_type()
            platform = get_platform(magic_type)
            if platform == "linux" and not linux_enabled and "Python" not in magic_type:
                continue

            if File(filename).get_size() > web_cfg.general.max_sample_size and not (
                web_cfg.general.allow_ignore_size and "ignore_size_check" in options
            ):
                if web_cfg.general.enable_trim:
                    # maybe identify here
                    if trim_file(filename):
                        filename = trimmed_path(filename)
            new_retlist.append((filename, platform))
    return new_retlist[:10]
