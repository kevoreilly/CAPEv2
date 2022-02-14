# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
from datetime import datetime

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File, IsPEImage

log = logging.getLogger(__name__)

processing_conf = Config("processing")

HAVE_FLARE_CAPA = False
# required to not load not enabled dependencies
if processing_conf.flare_capa.enabled and not processing_conf.flare_capa.on_demand:
    from lib.cuckoo.common.integrations.capa import HAVE_FLARE_CAPA, flare_capa_details


class PortableExecutable(object):
    """PE analysis."""

    def __init__(self, file_path, results):
        """@param file_path: file path."""
        self.file_path = file_path
        self.pe = None
        self.results = results

    def add_statistic(self, name, field, value):
        self.results["statistics"]["processing"].append({"name": name, field: value})

    def add_statistic_tmp(self, name, field, pretime):
        posttime = datetime.now()
        timediff = posttime - pretime
        value = float(f"{timediff.seconds}.{timediff.microseconds // 1000:03d}")

        if name not in self.results["temp_processing_stats"]:
            self.results["temp_processing_stats"][name] = {}

        # To be able to add yara/capa and others time summary over all processing modules
        if field in self.results["temp_processing_stats"][name]:
            self.results["temp_processing_stats"][name][field] += value
        else:
            self.results["temp_processing_stats"][name][field] = value

    def _get_guest_digital_signers(self):
        retdata = {}
        cert_data = {}
        cert_info = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.results["info"]["id"]), "aux", "DigiSig.json")

        if os.path.exists(cert_info):
            with open(cert_info, "r") as cert_file:
                buf = cert_file.read()
            if buf:
                cert_data = json.loads(buf)

        if cert_data:
            retdata = {
                "aux_sha1": cert_data["sha1"],
                "aux_timestamp": cert_data["timestamp"],
                "aux_valid": cert_data["valid"],
                "aux_error": cert_data["error"],
                "aux_error_desc": cert_data["error_desc"],
                "aux_signers": cert_data["signers"],
            }

        return retdata

    def run(self):
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not os.path.exists(self.file_path):
            log.debug("File doesn't exist anymore")
            return {}

        # Advanced check if is real PE
        if not IsPEImage(open(self.file_path, "rb").read()):
            return {}

        results = {}
        peresults = results["pe"] = {}
        results["pe"], _ = File(self.file_path).get_all()
        peresults["guest_signers"] = self._get_guest_digital_signers()
        if HAVE_FLARE_CAPA:
            pretime = datetime.now()
            capa_details = flare_capa_details(self.file_path, "static")
            if capa_details:
                results["flare_capa"] = capa_details
            self.add_statistic_tmp("flare_capa", "time", pretime)

        return results
