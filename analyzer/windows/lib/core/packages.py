# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import re
from lib.common.decode_vbe_jse import DecodeVBEJSE


def choose_package(file_type, file_name, exports, target):
    """Choose analysis package due to file type and file extension.
    @param file_type: file type.
    @param file_name: file name.
    @return: package name or None.
    """
    if not file_type:
        return None

    file_name = file_name.lower()
    file_content = open(target, "rb").read()

    if "Nullsoft Installer" in file_type:
        return "nsis"
    elif "DLL" in file_type:
        if file_name.endswith(".cpl"):
            return "cpl"
        else:
            if exports:
                explist = exports.split(",")
                if "DllRegisterServer" in explist:
                    return "regsvr"
            return "dll"
    elif "PE32" in file_type or "MS-DOS" in file_type:
        return "exe"
    elif file_name.endswith((".msi",".msp",".appx")) or "MSI Installer" in file_type:
        return "msi"    
    elif "PDF" in file_type or file_name.endswith(".pdf"):
        return "pdf"
    elif file_name.endswith(".pub"):
        return "pub"
    elif (
        "Rich Text Format" in file_type
        or "Microsoft Word" in file_type
        or "Microsoft Office Word" in file_type
        or "Microsoft OOXML" in file_type
        or "MIME entity" in file_type
        or file_name.endswith((".doc", ".dot", ".docx", ".dotx", ".docm", ".dotm", ".docb", ".rtf", ".mht", ".mso"))
    ):
        return "doc"
    elif (
        "Microsoft Office Excel" in file_type
        or "Microsoft Excel" in file_type
        or file_name.endswith((".xls", ".xlt", ".xlm", ".xlsx", ".xltx", ".xlsm", ".xltm", ".xlsb", ".xla", ".xlam", ".xll", ".xlw", ".slk"))
    ):
        return "xls"
    elif "PowerPoint" in file_type or file_name.endswith(
        (".ppt", ".pot", ".pps", ".pptx", ".pptm", ".potx", ".potm", ".ppam", ".ppsx", ".ppsm", ".sldx", ".sldm")
    ):
        return "ppt"
    elif "Java Jar" in file_type or "Java archive" in file_type or file_name.endswith(".jar"):
        return "jar"
    elif "Zip" in file_type:
        return "zip"
    elif "RAR archive" in file_type or file_name.endswith(".rar"):
        return "rar"
    elif "Macromedia Flash" in file_type or file_name.endswith(".swf") or file_name.endswith(".fws"):
        return "swf"
    elif file_name.endswith((".py", ".pyc")) or "Python script" in file_type:
        return "python"
    elif file_name.endswith(".ps1"):
        return "ps1"
    elif file_name.endswith(".msg"):
        return "msg"
    elif file_name.endswith(".eml") or file_name.endswith(".ics") or "vCalendar calendar" in file_type:
        return "eml"
    elif file_name.endswith(".js") or file_name.endswith(".jse"):
        return "js"
    elif file_name.endswith((".htm", ".html")):
        return "html"
    elif file_name.endswith(".hta"):
        return "hta"
    elif file_name.endswith(".xps"):
        return "xps"
    elif file_name.endswith(".wsf") or file_type == "XML document text":
        return "wsf"
    elif "HTML" in file_type:
        return "html"
    elif file_name.endswith(".mht"):
        return "mht"
    elif file_name.endswith(".url") or "MS Windows 95 Internet shortcut" in file_type or "Windows URL shortcut" in file_type:
        return "html"
    elif b"mso-application" in file_content and b"Word.Document" in file_content:
        return "doc"
    elif file_name.endswith(".lnk") or "MS Windows shortcut" in file_type:
        return "lnk"
    elif file_name.endswith(".chm") or "MS Windows HtmlHelp Data" in file_type:
        return "chm"
    elif file_name.endswith((".hwp", ".hwpx", ".hwt", ".hml")) or "Hangul (Korean) Word Processor File" in file_type:
        return "hwp"
    elif file_name.endswith((".inp", ".int")) or b"InPage Arabic Document" in file_content:
        return "inp"
    elif file_name.endswith(".vbs") or file_name.endswith(".vbe") or re.findall(br"\s?Dim\s", file_content, re.I):
        return "vbs"
    elif b"#@~^" in file_content[:100]:
        data = DecodeVBEJSE(file_content, "")
        if data:
            if re.findall(br"\s?Dim\s", data, re.I):
                return "vbs"
            else:
                return "js"
        else:
            return "vbejse"
    else:
        return "generic"
