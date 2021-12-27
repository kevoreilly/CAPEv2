from __future__ import absolute_import, print_function
import json
import logging

import requests

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_REPORTED, Database

log = logging.getLogger(__name__)
main_db = Database()
repconf = Config("reporting")


class CALLBACKHOME(Report):
    "Notify us about analysis is done"

    order = 10000  # used in the reporting module and required here.

    def run(self, results):
        urls = repconf.callback.url.split(",")
        task_id = int(results.get("info", {}).get("id"))
        """Handles a possible race condition where the status is not updated before the callback is consumed."""
        # set completed_on time
        main_db.set_status(task_id, TASK_COMPLETED)
        # set reported time
        main_db.set_status(task_id, TASK_REPORTED)
        for url in urls:
            try:
                for value in (task_id, str(task_id)):
                    res = requests.post(url, data=json.dumps({"task_id": value}), timeout=20)
                    if res and res.ok:
                        log.debug("reported id: %d", task_id)
                    else:
                        log.error("failed to report %d", task_id)
            except Exception as e:
                log.exception(e)
