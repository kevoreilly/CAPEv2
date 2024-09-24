# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re


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
        elif file_name.endswith(".xll"):
            return "xls"
        else:
            if exports:
                explist = exports.split(",")
                if "DllRegisterServer" in explist:
                    return "regsvr"
            return "dll"
    elif "PE32" in file_type or "MS-DOS" in file_type:
        return "exe"
    elif file_name.endswith((".msi", ".msp", ".appx")) or "MSI Installer" in file_type:
        return "msi"
    elif file_name.endswith(".pub"):
        return "pub"
    elif file_name.endswith(".one"):
        return "one"
    elif (
        "Rich Text Format" in file_type
        or "Microsoft Word" in file_type
        or "Microsoft Office Word" in file_type
        or "Microsoft OOXML" in file_type
        or "MIME entity" in file_type
        or file_name.endswith(
            (".asd", ".doc", ".dot", ".docx", ".dotx", ".docm", ".dotm", ".docb", ".rtf", ".mht", ".mso", ".wbk", ".wiz")
        )
    ):
        return "doc"
    elif (
        "Microsoft Office Excel" in file_type
        or "Microsoft Excel" in file_type
        or file_name.endswith(
            (".xls", ".xlt", ".xlm", ".xlsx", ".xltx", ".xlsm", ".xltm", ".xlsb", ".xla", ".xlam", ".xll", ".xlw", ".slk", ".csv")
        )
    ):
        return "xls"
    elif "PowerPoint" in file_type or file_name.endswith(
        (".ppt", ".ppa", ".pot", ".pps", ".pptx", ".pptm", ".potx", ".potm", ".ppam", ".ppsx", ".ppsm", ".sldx", ".sldm")
    ):
        return "ppt"
    elif b"MANIFEST" in file_content or "Java Jar" in file_type or "Java archive" in file_type or file_name.endswith(".jar"):
        return "jar"
    elif "Zip" in file_type:
        return "zip"
    elif "RAR archive" in file_type or file_name.endswith(".rar"):
        return "rar"
    elif "Macromedia Flash" in file_type or file_name.endswith((".swf", ".fws")):
        return "swf"
    elif file_name.endswith((".py", ".pyc")) or "Python script" in file_type or b"import" in file_content:
        return "python"
    elif file_name.endswith(".ps1"):
        return "ps1"
    elif file_name.endswith((".msg", ".rpmsg")) or "rpmsg Restricted Permission Message" in file_type:
        return "msg"
    elif file_name.endswith((".eml", ".ics")) or (
        "RFC 822 mail" in file_type
        or "old news" in file_type
        or "mail forwarding" in file_type
        or "smtp mail" in file_type
        or "news" in file_type
        or "news or mail" in file_type
        or "saved news" in file_type
        or "MIME entity" in file_type
        or "vCalendar calendar" in file_type
    ):
        return "eml"
    elif file_name.endswith((".js", ".jse")):
        return "js"
    elif file_name.endswith(".hta"):
        return "hta"
    elif file_name.endswith(".xps"):
        return "xps"
    elif "HTML" in file_type:
        if file_name.endswith(".wsf") or file_name.endswith(".wsc"):
            return "wsf"
        elif re.search(b'(?:<hta\\:application|<script\\s+language\\s*=\\s*"(J|VB|Perl)Script")', file_content, re.I):
            return "html"
        else:
            return "chrome"
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
    elif file_name.endswith((".xsl", ".xslt")) or "XSL stylesheet" in file_type:
        return "xslt"
    elif file_name.endswith(".sct"):
        if re.search(rb"(?is)<\?XML.*?<scriptlet.*?<registration", file_content):
            return "sct"
        else:
            return "hta"
    elif file_name.endswith(".wsf") or file_type == "XML document text":
        return "wsf"
    elif "PDF" in file_type or file_name.endswith(".pdf"):
        return "pdf"
    elif re.search(b'<script\\s+language="(J|VB|Perl)Script"', file_content, re.I):
        return "wsf"
    elif (
        file_name.endswith((".vbs", ".vbe"))
        or re.findall(rb"\s?Dim\s", file_content, re.I)
        or re.findall(rb"\s?\x00D\x00i\x00m\x00\s", file_content, re.I)
    ):
        return "vbs"
    elif b"Set-StrictMode" in file_content[:100]:
        return "ps1"
    elif file_name.endswith((".csproj", ".vbproj", ".vcxproj", ".dbproj", "fsproj")) or b"msbuild" in file_content:
        return "msbuild"
    elif file_name.endswith((".jtd", ".jtdc", ".jttc", ".jtt")):
        return "ichitaro"
    elif file_name.endswith(".reg"):
        return "reg"
    elif "ISO 9660" in file_type or file_name.endswith((".iso", ".udf", ".vhd")):
        return "archive"
    elif file_name.endswith(".a3x"):
        return "autoit"
    elif file_name.endswith(("cmd", "bat")) or b"@echo off" in file_content:
        return "batch"
    else:
        return "generic"
