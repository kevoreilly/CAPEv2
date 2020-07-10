from __future__ import absolute_import
from __future__ import print_function
import os
import sys
from datetime import datetime, timedelta

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(".")), ".."))
from lib.cuckoo.common.config import Config

repconf = Config("reporting")
last_24 = (datetime.now() - timedelta(days=1)).isoformat()
FULL_DB = False
if repconf.mongodb.enabled:
    import pymongo

    results_db = pymongo.MongoClient(repconf.mongodb.host, repconf.mongodb.port)[repconf.mongodb.db]
    data = results_db.analysis.find({"statistics": {"$exists": True}, "info.started": {"$gte": last_24}})
    if data:
        end_data = dict()
        for anal in data:
            if "statistics" in anal:
                for type_entry in anal["statistics"]:
                    if type_entry not in end_data:
                        end_data.setdefault(type_entry, dict())
                    for entry in anal["statistics"][type_entry]:
                        if entry["name"] not in end_data[type_entry]:
                            end_data[type_entry].setdefault(entry["name"], dict())
                            end_data[type_entry][entry["name"]] = entry["time"]
                        else:
                            end_data[type_entry][entry["name"]] += entry["time"]

for module_name in [u"signatures", u"processing", u"reporting"]:
    s = sorted(end_data[module_name], key=end_data[module_name].get, reverse=True)[:10]
    print(module_name)
    for entry in s:
        print(("\t", entry, end_data[module_name][entry]))
    print("\n")
