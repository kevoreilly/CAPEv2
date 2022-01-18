import logging

from lib.cuckoo.common.config import Config

# CAPE_ROOT = os.path.join(os.path.abspath(), "..")
# sys.path.append(CAPE_ROOT)

log = logging.getLogger(__name__)
repconf = Config("reporting")

conn = False
mdb = repconf.mongodb.get("db", "cuckoo")
# Check if MongoDB reporting is enabled and drop that if it is.
if repconf.mongodb.enabled:
    from pymongo import MongoClient

    try:
        conn = MongoClient(
            host=repconf.mongodb.get("host", "127.0.0.1"),
            port=repconf.mongodb.get("port", 27017),
            username=repconf.mongodb.get("username"),
            password=repconf.mongodb.get("password"),
            authSource=repconf.mongodb.get("authsource", "cuckoo"),
        )
    except Exception as e:
        log.warning("Unable to connect to MongoDB database: {}, {}".format(mdb, e))


# code.interact(local=dict(locals(), **globals()))
# q = results_db.analysis.find({"info.id": 26}, {"memory": 1})


results_db = conn[mdb]


def delete_mongo_data(task_id):
    try:
        task = results_db.analysis.find_one({"info.id": task_id}, {"behavior.processes.calls": 1})
        for process in task.get("behavior", {}).get("processes", []) or []:
            if process.get("calls"):
                results_db.calls.delete_many({"_id": {"$in": process["calls"]}})
        results_db.analysis.delete_one({"info.id": task_id})
    except Exception as e:
        log.error(e, exc_info=True)
