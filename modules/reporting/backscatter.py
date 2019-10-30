from __future__ import absolute_import
import os
import requests
import logging
from io import BytesIO
from zipfile import ZipFile
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT



log = logging.getLogger(__name__)
reporting_conf = Config("reporting")

class BACKSCATTER(Report):
    "Notify us about analysis is done"
    order = 10000



    def zip_files(self, files):
        in_memory = BytesIO()
        zf = ZipFile(in_memory, mode="w")

        for file in files:
            zf.writestr(os.path.basename(file), open(file, "rb").read())

        zf.close()
        in_memory.seek(0)

        #read the data
        data = in_memory.read()
        in_memory.close()

        return data

    def run(self, results):
        task_id = str(results.get('info', {}).get('id'))
        report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id)
        log.info("backscatter enabled")
        #zip dropped/memory and send it to
        files = dict()
        try:
            if os.path.exists(os.path.join(report_path, "binary")):
                files['sample'] = self.zip_files([os.path.join(report_path, "binary")])
        except AttributeError as e:
            log.error(e)

        compres_files = list()
        for folder in ("dropped", "files", "memory"):
            log.info("Compressing files for backscatter from folder: {}".format(folder))
            if os.path.exists(os.path.join(report_path, folder)):
                try:
                    compres_files += [os.path.join(report_path, folder, file) for file in os.listdir(os.path.join(report_path, folder)) if not file.endswith(("_info", ".strings"))]
                except AttributeError as e:
                    log.error(e)

            if compres_files:
                files["vmi_sandbox_output"] = self.zip_files(compres_files)
            if files:
                log.info("we have files for backscatter")
                try:
                    r = requests.post(reporting_conf.backscatter.url,
                        params={
                            "callback_uri": reporting_conf.backscatter.callback_url+ "/"+task_id+"/",
                            "format": reporting_conf.backscatter.format
                        },
                        files=files,
                        headers={"X-Source": "TCR - Cuckoo", "X-Contact": "TCR"},
                        verify=False,
                        timeout=30,
                    )
                    log.info("files sent")
                    log.info((r.status_code, r.url, r.content))
                except Exception as e:
                    log.error(e)
