import os
import shutil
import sys

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(".")), "..")
sys.path.append(CUCKOO_ROOT)


from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists

repconf = Config("reporting")

# this required for Iocs API
FULL_DB = False
if repconf.mongodb.enabled:
    import pymongo
    from bson.objectid import ObjectId

    results_db = pymongo.MongoClient(
        repconf.mongodb.host,
        port=repconf.mongodb.port,
        username=repconf.mongodb.get("username"),
        password=repconf.mongodb.get("password"),
        authSource=repconf.mongodb.get("authsource", "cuckoo"),
    )[repconf.mongodb.db]
    FULL_DB = True

if repconf.elasticsearchdb.enabled:
    from dev_utils.elasticsearchdb import (
        delete_analysis_and_related_calls,
        elastic_handler,
        get_analysis_index,
        get_query_by_info_id,
    )

    es = elastic_handler


# Used for displaying enabled config options in Django UI
enabledconf = {}
for cfile in ("reporting", "processing", "auxiliary", "web"):
    curconf = Config(cfile)
    confdata = curconf.get_config()
    for item in confdata:
        if "enabled" in confdata[item]:
            if confdata[item]["enabled"] == "yes":
                enabledconf[item] = True
            else:
                enabledconf[item] = False


def remove(task_id):
    if repconf.mongodb.enabled or repconf.elasticsearchdb.enabled:
        if repconf.mongodb.enabled:
            analyses = list(results_db.analysis.find({"info.id": int(task_id)}, {"_id": 1, "behavior.processes": 1}))
        elif repconf.elasticsearchdb.enabled:
            analyses = [
                d["_source"]
                for d in es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id), _source=["behavior.processes"])[
                    "hits"
                ]["hits"]
            ]
        else:
            analyses = []

        if len(analyses) > 0:
            # Delete dups too.
            for analysis in analyses:
                if repconf.mongodb.enabled:
                    # Delete calls.
                    for process in analysis.get("behavior", {}).get("processes", []):
                        for call in process["calls"]:
                            results_db.calls.delete_one({"_id": ObjectId(call)})
                    # Delete analysis data.
                    results_db.analysis.delete_one({"_id": ObjectId(analysis["_id"])})
                elif repconf.elasticsearchdb.enabled:
                    delete_analysis_and_related_calls(analysis["info"]["id"])

            analyses_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id)
            if path_exists(analyses_path):
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
