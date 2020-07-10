# Copyright (C) 2017  enzok
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import
import os
import logging
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File

log = logging.getLogger(__name__)

try:
    from mmbot import MaliciousMacroBot

    HAVE_MMBOT = True
except:
    HAVE_MMBOT = False


class MMBot(Processing):
    """MaliciousMacroBot analysis.
    @return: malicious label and scores
    7"""

    def run(self):
        self.key = "mmbot"
        results = dict()
        ftype = File(self.file_path).get_type()

        if self.task["category"] == "file":
            if not HAVE_MMBOT:
                log.error("MaliciousMacroBot not installed, 'pip3 install mmbot', aborting mmbot analysis.")
                return results

            package = ""
            if "info" in self.results and "package" in self.results["info"]:
                package = self.results["info"]["package"]

            if package not in ("doc", "ppt", "xls", "pub") and (
                "Zip archive data, at least v2.0" not in ftype
                or "Composite Document File V2 Document" not in ftype
                or "Microsoft OOXML" not in ftype
            ):
                return results

            opts = dict()
            opts["benign_path"] = self.options.get("benign_path", os.path.join(CUCKOO_ROOT, "data", "mmbot", "benign"))
            opts["malicious_path"] = self.options.get("malicious_path", os.path.join(CUCKOO_ROOT, "data", "mmbot", "malicious"))
            opts["model_path"] = self.options.get("model_path", os.path.join(CUCKOO_ROOT, "data", "mmbot", "model"))

            try:
                mmb = MaliciousMacroBot(opts["benign_path"], opts["malicious_path"], opts["model_path"], retain_sample_contents=False)

                mmb.mmb_init_model(modelRebuild=False)
                predresult = mmb.mmb_predict(self.file_path)
                results = mmb.mmb_prediction_to_json(predresult)[0]

                if "malicious" in results["prediction"]:
                    link_path = os.path.join(opts["malicious_path"], os.path.basename(self.file_path))
                    if not os.path.isfile(link_path):
                        os.symlink(self.file_path, link_path)
                elif "benign" in results["prediction"]:
                    link_path = os.path.join(opts["benign_path"], os.path.basename(self.file_path))
                    if not os.path.isfile(link_path):
                        os.symlink(self.file_path, link_path)

            except Exception as xcpt:
                log.error("Failed to run mmbot processing: %s", xcpt)

        return results
