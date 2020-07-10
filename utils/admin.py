from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import shutil

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(".")), "..")
sys.path.append(CUCKOO_ROOT)


from lib.cuckoo.core.database import Database, Task, TASK_PENDING
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.web_utils import perform_malscore_search, perform_search, perform_ttps_search, search_term_map
import modules.processing.network as network

repconf = Config("reporting")

# this required for Iocs API
FULL_DB = False
if repconf.mongodb.enabled:
    import pymongo
    from bson.objectid import ObjectId

    results_db = pymongo.MongoClient(
        repconf.mongodb.host,
        port=repconf.mongodb.port,
        username=repconf.mongodb.get("username", None),
        password=repconf.mongodb.get("password", None),
        authSource=repconf.mongodb.db,
    )[repconf.mongodb.db]
    FULL_DB = True


# Used for displaying enabled config options in Django UI
enabledconf = dict()
for cfile in ["reporting", "processing", "auxiliary", "web"]:
    curconf = Config(cfile)
    confdata = curconf.get_config()
    for item in confdata:
        if "enabled" in confdata[item]:
            if confdata[item]["enabled"] == "yes":
                enabledconf[item] = True
            else:
                enabledconf[item] = False


def remove(task_id):

    if enabledconf["mongodb"]:
        analyses = results_db.analysis.find({"info.id": int(task_id)}, {"_id": 1, "behavior.processes": 1})
        # Checks if more analysis found with the same ID, like if process.py was run manually.
        if analyses.count() > 1:
            message = "Multiple tasks with this ID deleted."
        elif analyses.count() == 1:
            message = "Task deleted."

        if analyses.count() > 0:
            # Delete dups too.
            for analysis in analyses:
                # Delete calls.
                for process in analysis.get("behavior", {}).get("processes", []):
                    for call in process["calls"]:
                        results_db.calls.remove({"_id": ObjectId(call)})
                # Delete analysis data.
                results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})
            analyses_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id)
            if os.path.exists(analyses_path):
                shutil.rmtree(analyses_path)
        else:
            print("nothing found")


ids = sys.argv[1]
if "," in ids:
    ids = ids.split(",")
else:
    ids = [ids]
for id in ids:
    remove(id)
