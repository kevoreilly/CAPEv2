from __future__ import absolute_import
from __future__ import print_function
import json
import requests
import logging
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database, TASK_COMPLETED, TASK_REPORTED

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
    HAVE_MONGO = True
except ImportError:
    HAVE_MONGO = False
    print("missed pymongo")

log = logging.getLogger(__name__)
main_db = Database()
reporting_conf = Config("reporting")

class CALLBACKHOME(Report):
    "Notify us about analysis is done"
    order = 10000

    def run(self, results):
        urls = reporting_conf.callback.url.split(",")
        task_id = int(results.get('info', {}).get('id'))
        #mark as reported
        if HAVE_MONGO:
            try:
                conn = pymongo.MongoClient( reporting_conf.mongodb.host,
                                port=reporting_conf.mongodb.port,
                                username=reporting_conf.mongodb.get("username", None),
                                password=reporting_conf.mongodb.get("password", None),
                                authSource=reporting_conf.mongodb.db
                                )
                mongo_db = conn[reporting_conf.mongodb.db]
                # set complated_on time
                main_db.set_status(task_id, TASK_COMPLETED)
                # set reported time
                main_db.set_status(task_id, TASK_REPORTED)
                conn.close()
            except ConnectionFailure:
                log.error("Cannot connect to MongoDB")

            for url in urls:
                try:
                    sucesss = False
                    for value in (task_id, str(task_id)):
                        # try task_id as an integer and as a string too
                        res = requests.post(url, data=json.dumps({"task_id": value}), timeout=20)
                        if res and res.ok:
                            success = True
                            break
                    if success:
                        log.debug("reported id: {}".format(task_id))
                    else:
                        log.error("failed to report {}".format(task_id))
                except Exception as e:
                    log.exception(e)
