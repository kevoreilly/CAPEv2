#!/usr/local/bin/python
# -*- coding: latin-1 -*-
"""
ExtractMsg:
    Extracts emails and attachments saved in Microsoft Outlook's .msg files

https://github.com/mattgwwalker/msg-extractor
"""

from __future__ import absolute_import
import six

__author__ = "Matthew Walker"
__date__ = "2013-11-19"
__version__ = "0.2"

# --- LICENSE -----------------------------------------------------------------
#
#    Copyright 2013 Matthew Walker, 2015 Optiv, Inc. (brad.spengler@optiv.com)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import glob
import traceback
from email.parser import Parser as EmailParser
import email.utils
import olefile as OleFile
from lib.cuckoo.common.utils import store_temp_file


def windowsUnicode(string):
    if string is None:
        return None
    if sys.version_info[0] >= 3:  # Python 3
        return str(string, "utf_16_le")
    else:  # Python 2
        return six.text_type(string, "utf_16_le")


class Attachment:
    def __init__(self, msg, dir_):
        # Get long filename
        self.longFilename = msg._getStringStream([dir_, "__substg1.0_3707"])

        # Get short filename
        self.shortFilename = msg._getStringStream([dir_, "__substg1.0_3704"])

        # Get attachment data
        self.data = msg._getStream([dir_, "__substg1.0_37010102"])

    def save(self):
        # Use long filename as first preference
        filename = self.longFilename
        # Otherwise use the short filename
        if filename is None:
            filename = self.shortFilename
        # Otherwise just make something up!
        if filename is None:
            import random
            import string

            filename = "UnknownAttachment" + "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5)) + ".bin"

        base, ext = os.path.splitext(filename)
        basename = os.path.basename(filename)
        ext = ext.lower()
        if ext == "" and len(basename) and basename[0] == ".":
            return None
        extensions = [
            "",
            ".exe",
            ".dll",
            ".com",
            ".pdf",
            ".msi",
            ".bin",
            ".scr",
            ".zip",
            ".tar",
            ".tgz",
            ".gz",
            ".rar",
            ".htm",
            ".html",
            ".hta",
            ".doc",
            ".dot",
            ".docx",
            ".dotx",
            ".docm",
            ".dotm",
            ".docb",
            ".mht",
            ".mso",
            ".js",
            ".jse",
            ".vbs",
            ".vbe",
            ".xls",
            ".xlt",
            ".xlm",
            ".xlsx",
            ".xltx",
            ".xlsm",
            ".xltm",
            ".xlsb",
            ".xla",
            ".xlam",
            ".xll",
            ".xlw",
            ".ppt",
            ".pot",
            ".pps",
            ".pptx",
            ".pptm",
            ".potx",
            ".potm",
            ".ppam",
            ".ppsx",
            ".ppsm",
            ".sldx",
            ".sldm",
            ".wsf",
        ]
        foundext = False
        for theext in extensions:
            if ext == theext:
                foundext = True
                break

        if not foundext:
            return None

        return store_temp_file(self.data, filename)


class Message(OleFile.OleFileIO):
    def __init__(self, filename):
        OleFile.OleFileIO.__init__(self, filename)

    def _getStream(self, filename):
        if self.exists(filename):
            stream = self.openstream(filename)
            return stream.read()
        else:
            return None

    def _getStringStream(self, filename, prefer="unicode"):
        """Gets a string representation of the requested filename.
        Checks for both ASCII and Unicode representations and returns
        a value if possible.  If there are both ASCII and Unicode
        versions, then the parameter /prefer/ specifies which will be
        returned.
        """

        if isinstance(filename, list):
            # Join with slashes to make it easier to append the type
            filename = "/".join(filename)

        asciiVersion = self._getStream(filename + "001E")
        unicodeVersion = windowsUnicode(self._getStream(filename + "001F"))
        if asciiVersion is None:
            return unicodeVersion
        elif unicodeVersion is None:
            return asciiVersion
        else:
            if prefer == "unicode":
                return unicodeVersion
            else:
                return asciiVersion

    @property
    def body(self):
        # Get the message body
        return self._getStringStream("__substg1.0_1000")

    @property
    def attachments(self):
        try:
            return self._attachments
        except Exception:
            # Get the attachments
            attachmentDirs = []

            for dir_ in self.listdir():
                if dir_[0].startswith("__attach") and dir_[0] not in attachmentDirs:
                    attachmentDirs.append(dir_[0])

            self._attachments = []

            for attachmentDir in attachmentDirs:
                self._attachments.append(Attachment(self, attachmentDir))

            return self._attachments

    def get_extracted_attachments(self):
        retlist = []
        # Save the attachments
        for attachment in self.attachments:
            saved = attachment.save()
            if saved:
                retlist.append(saved)

        return retlist
