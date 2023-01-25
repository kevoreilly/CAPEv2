# Copyright (C) 2010-2015 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import locale
import logging
import os
from io import BytesIO
from pathlib import Path

from lib.api.utils import Utils
from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile

log = logging.getLogger(__name__)
util = Utils()


class DigiSig(Auxiliary):
    """Runs signtool.exe and parses the output.

    For this to work, the Microsoft tool signtool.exe will need to be placed
    into the windows/analyzer/bin/ directory. signtool.exe can be downloaded
    from Microsoft as part of the SDK. (which is also usually packaged with
    Visual Studio)

    TODO:
    Currently the only way to properly update root certificate cab files is
    via Windows Update which is disabled in many Cuckoo rigs. This means that
    we will not be able to error out on revoked certificates. Need to find a
    good work around for this. Ideally make it an option so we don't force
    log unnecessary update network traffic.
    """

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.config = config
        self.enabled = self.config.digisig
        self.cert_build = []
        self.time_build = []
        self.json_data = {"sha1": None, "signers": [], "timestamp": None, "valid": False, "error": None, "error_desc": None}

    def build_output(self, outputType, line):
        if line:
            if outputType == "cert":
                self.cert_build.append(line.replace("    ", "-"))
            elif outputType == "time":
                self.time_build.append(line.replace("    ", "-"))

    def parse_digisig(self, data):
        parser_switch = None
        for line in data.splitlines():
            if line.startswith(("Hash of file (sha1)", "SHA1 hash of file")) and not self.json_data["sha1"]:
                self.json_data["sha1"] = line.rsplit(": ", 1)[-1].lower()
            # Start of certificate chain information
            if line.startswith("Signing Certificate Chain:"):
                parser_switch = "cert"
                continue
            # End of certificate chain information
            if line.startswith("The signature is timestamped:"):
                parser_switch = None
                if not self.json_data["timestamp"]:
                    self.json_data["timestamp"] = line.rsplit(": ", 1)[-1]
            if line.startswith("File is not timestamped."):
                parser_switch = None
            # Start of timestamp verification
            if line.startswith("Timestamp Verified by:"):
                parser_switch = "time"
                continue
            # Potential end of timestamp verification
            if line.startswith("File has page hashes"):
                parser_switch = None
            # Potential end of timestamp verification
            if line.startswith("Number of files"):
                parser_switch = None
            # Potential end of timestamp verification
            if line.startswith("Successfully verified"):
                parser_switch = None
            if parser_switch == "cert":
                self.build_output("cert", line)
            elif parser_switch == "time":
                self.build_output("time", line)

    def jsonify(self, signType, signers):
        buf = {}
        lastnum = 0
        for item in signers:
            key, value = item.split(":", 1)
            num = key.count("-")
            signed = f"{signType} {num}"
            if lastnum != num and buf:
                self.json_data["signers"].append(buf)
                buf = {}
            key = key.replace("-", "")
            value = value.strip()
            buf["name"] = signed
            # Lower case hashes to match the format of other hashes in Django
            buf[key] = value.lower() if key == "SHA1 hash" else value
            lastnum = num

        if buf:
            self.json_data["signers"].append(buf)

    def start(self):
        if not self.enabled:
            return False
        try:
            if self.config.category != "file":
                log.debug("Skipping authenticode validation, analysis is not a file")
                return True

            sign_path = os.path.join(Path.cwd(), "bin", "signtool.exe")
            if not os.path.exists(sign_path):
                log.info("Skipping authenticode validation, signtool.exe was not found in bin/")
                return True

            log.debug("Checking for a digital signature")
            file_path = os.path.join(os.environ["TEMP"] + os.sep, str(self.config.file_name))
            cmd = f'{sign_path} verify /pa /v "{file_path}"'
            ret, out, err = util.cmd_wrapper(cmd)
            out = out.decode(locale.getpreferredencoding(), errors="ignore")

            # Return was 0, authenticode certificate validated successfully
            if not ret:
                _ = self.parse_digisig(out)
                self.jsonify("Certificate Chain", self.cert_build)
                self.jsonify("Timestamp Chain", self.time_build)
                self.json_data["valid"] = True
                log.debug("File has a valid signature")
            # Non-zero return, it didn't validate or exist
            else:
                self.json_data["error"] = True
                errmsg = b" ".join(err.split(b":", 1)[1].split())
                self.json_data["error_desc"] = errmsg.decode()
                if b"file format cannot be verified" in err:
                    log.debug("File format not recognized")
                elif b"No signature found" not in err:
                    log.debug("File has an invalid signature")
                    _ = self.parse_digisig(out)
                    self.jsonify("Certificate Chain", self.cert_build)
                    self.jsonify("Timestamp Chain", self.time_build)
                else:
                    log.debug("File is not signed")

            if self.json_data:
                log.info("Uploading signature results to aux/%s.json", self.__class__.__name__)
                with BytesIO() as upload:
                    upload.write(json.dumps(self.json_data, ensure_ascii=False).encode())
                    upload.seek(0)
                    nf = NetlogFile()
                    nf.init("aux/DigiSig.json")
                    for chunk in upload:
                        nf.sock.send(chunk)
                    nf.close()

        except Exception as e:
            print(e)
            import traceback

            log.exception(traceback.format_exc())

        return True
