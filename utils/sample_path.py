from __future__ import absolute_import, print_function
import os
import sys

import pymongo

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database

repconf = Config("reporting")
if len(sys.argv) == 2:
    db = Database()
    paths = db.sample_path_by_hash(sys.argv[1])
    if paths is not None:
        paths = [path for path in paths if os.path.exists(path)]
        if paths:
            print(("Found by db.sample_path_by_hash: {}".format(sys.argv[1])))
            print(paths)
    else:
        if repconf.mongodb.enabled:
            results_db = pymongo.MongoClient(
                repconf.mongodb.host,
                port=repconf.mongodb.port,
                username=repconf.mongodb.get("username"),
                password=repconf.mongodb.get("password"),
                authSource=repconf.mongodb.get("authsource", "cuckoo"),
            )[repconf.mongodb.db]
            tasks = results_db.analysis.find({"dropped.sha256": sys.argv[1]})
        elif repconf.elasticsearchdb.enabled:
            from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index
            tasks = [d['_source'] for d in elastic_handler.search(
                index=get_analysis_index(), body={
                    "query": {
                        "match": {
                            "dropped.sha256": sys.argv[1]
                        }
                    }
                })['hits']['hits']]
        else:
            tasks = []

        if tasks:
            for task in tasks:
                path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["info"]["id"]), "files", sys.argv[1])
                if os.path.exists(path):
                    paths = [path]
                    print(("Found by dropped in mongo: {}".format(sys.argv[1])))
                    break
else:
    print("provide hash to search")
