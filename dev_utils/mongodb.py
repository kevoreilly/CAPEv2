import os
import sys
import pymongo

CAPE_ROOT = os.path.join(os.path.abspath(os.path.dirname(".")), "..")
#CAPE_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CAPE_ROOT)

from lib.cuckoo.common.config import Config

repconf = Config("reporting")

results_db = pymongo.MongoClient(
    repconf.mongodb.host,
    port=repconf.mongodb.port,
    username=repconf.mongodb.get("username", None),
    password=repconf.mongodb.get("password", None),
    authSource=repconf.mongodb.db,
)[repconf.mongodb.db]

# import code;code.interact(local=dict(locals(), **globals()))
q = results_db.analysis.find({"info.id":26}, {"memory":1})
