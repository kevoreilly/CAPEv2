# import code
import os
import pymongo
import sys

from lib.cuckoo.common.config import Config

CAPE_ROOT = os.path.join(os.path.abspath(), "..")
sys.path.append(CAPE_ROOT)

repconf = Config("reporting")

results_db = pymongo.MongoClient(
    repconf.mongodb.host,
    port=repconf.mongodb.port,
    username=repconf.mongodb.get("username"),
    password=repconf.mongodb.get("password"),
    authSource=repconf.mongodb.authsource,
)[repconf.mongodb.db]

# code.interact(local=dict(locals(), **globals()))
q = results_db.analysis.find({"info.id": 26}, {"memory": 1})
