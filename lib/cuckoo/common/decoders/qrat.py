# Copyright (C) 2015 Kevin Breen (http://techanarchy.net), Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import sys
from zipfile import ZipFile
from struct import unpack
from lib.cuckoo.common.utils import store_temp_file
from subprocess import Popen, PIPE

try:
    import re2 as re
except ImportError:
    import re

# Basic Java Random implementation based on http://docs.oracle.com/javase/7/docs/api/java/util/Random.html
# so we don't need to add another dependency just for this config extractor


class JavaRandom(object):
    def __init__(self, seed):
        self.seed = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)

    def nextInt(self, n):
        self.seed = (self.seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        return (self.seed >> (48 - 31)) % n


def extract_config(file_path, decomp_jar):
    enckey = coded_jar = False

    if not decomp_jar:
        return None

    ret = {}

    try:
        with ZipFile(file_path, "r") as zip:
            for name in zip.namelist():
                if name == "e-data":
                    coded_data = zip.read(name)
                    seed = coded_data[:8]
                    enckey = unpack(">Q", seed)[0]

        if enckey and coded_data:
            java_rand = JavaRandom(enckey)
            coded_data = coded_data[8:]
            decoded_data = ""
            for i in range(len(coded_data)):
                key = java_rand.nextInt(255)
                dec_byte = chr((ord(coded_data[i]) - key + 256) % 256)
                decoded_data += dec_byte
            decoded_path = store_temp_file(decoded_data, "qrat.jar")

            try:
                p = Popen(["java", "-jar", decomp_jar, decoded_path], stdout=PIPE)
                decompiled_data = p.stdout.read()
            except:
                pass

            match = re.search("Utils\.serverHost = new String\[\] \{(?P<stringlist>[^};\r\n]*)\};", decompiled_data)
            if match:
                hostlist = match.group("stringlist").split(",")
                serverhosts = [x.strip(' "') for x in hostlist]
                for i in range(len(serverhosts)):
                    ret["ServerHost" + str(i)] = serverhosts[i]
            match = re.search("Utils\.serverPort = (?P<portnum>\d+);", decompiled_data)
            if match:
                ret["ServerPort"] = int(match.group("portnum"))
            match = re.search("Utils\.instanceControlPortAgent = (?P<portnum>\d+);", decompiled_data)
            if match:
                ret["InstanceControlPortAgent"] = int(match.group("portnum"))
            match = re.search("Utils\.instanceControlPortClient = (?P<portnum>\d+);", decompiled_data)
            if match:
                ret["InstanceControlPortClient"] = int(match.group("portnum"))

            try:
                os.unlink(decoded_path)
            except:
                pass

            return ret
    except:
        pass

    return None
