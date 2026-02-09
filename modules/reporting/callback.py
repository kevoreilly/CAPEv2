import json
import logging

import requests

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.data.task import TASK_REPORTED

log = logging.getLogger(__name__)
main_db = Database()


class CALLBACKHOME(Report):
    "Notify us about analysis is done"

    order = 10000  # used in the reporting module and required here.

    def run(self, results):
        urls = self.options.url.split(",")
        task_id = int(results.get("info", {}).get("id"))
        """Handles a possible race condition where the status is not updated before the callback is consumed."""
        # set completed_on time
        with Database().session.begin():
            Database().set_status(task_id, TASK_REPORTED)
        for url in urls:
            try:
                res = requests.post(url, headers={"Content-Type": "application/json"}, data=json.dumps({"task_id": task_id}), timeout=20)
                if res and res.ok:
                    log.debug("reported id: %d", task_id)
                else:
                    log.error("failed to report %d", task_id)
            except requests.exceptions.ConnectTimeout:
                log.error("Timeout when calling to callback: %s", url)
            except Exception as e:
                log.exception(e)
