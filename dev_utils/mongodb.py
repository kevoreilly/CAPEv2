import logging

from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)
repconf = Config("reporting")

mdb = repconf.mongodb.get("db", "cuckoo")


if repconf.mongodb.enabled:
    from pymongo import TEXT, MongoClient
    from pymongo.errors import ConnectionFailure, InvalidDocument, ServerSelectionTimeoutError


def connect_to_mongo():
    conn = False
    try:
        conn = MongoClient(
            host=repconf.mongodb.get("host", "127.0.0.1"),
            port=repconf.mongodb.get("port", 27017),
            username=repconf.mongodb.get("username"),
            password=repconf.mongodb.get("password"),
            authSource=repconf.mongodb.get("authsource", "cuckoo"),
        )
    except (ConnectionFailure, ServerSelectionTimeoutError):
        log.error("Cannot connect to MongoDB")
    except Exception as e:
        log.warning("Unable to connect to MongoDB database: {}, {}".format(mdb, e))

    return conn


# code.interact(local=dict(locals(), **globals()))
# q = results_db.analysis.find({"info.id": 26}, {"memory": 1})


results_db = connect_to_mongo()[mdb]


def mongo_create_index(collection, index, background=True, name=False):
    if name:
        getattr(results_db, collection).create_index(index, background=background, name=name)
    else:
        getattr(results_db, collection).create_index(index, background=background)


def mongo_insert_one(collection, query):
    return getattr(results_db, collection).insert_one(query)


def mongo_find(collection, query, projection):
    return getattr(results_db, collection).find(query, projection)


def mongo_delete_one(collection, query):
    return getattr(results_db, collection).delete_one(query)


def mongo_delete_many(collection, query):
    return getattr(results_db, collection).delete_many(query)


def mongo_find_one(collection, query, projection):
    return getattr(results_db, collection).find_one(query, projection)


def mongo_update(collection, query, projection):
    return getattr(results_db, collection).update(query, projection)


def mongo_update_one(collection, query, projection, bypass_document_validation=False):
    return getattr(results_db, collection).update_one(query, projection, bypass_document_validation=bypass_document_validation)


def mongo_aggregate(collection, query, projection):
    return getattr(results_db, collection).aggregate(query, projection)


def mongo_collection_names():
    if hasattr(results_db, "list_collection_names"):
        collection_names = results_db.list_collection_names()
    else:
        collection_names = results_db.collection_names()

    return collection_names


def mongo_drop_database(database):
    results_db.drop_database(database)


def delete_mongo_data(task_ids):
    try:
        if isinstance(task_ids, int):
            task_ids = [task_ids]

        analyses_tmp = []
        tasks = mongo_find("analysis", {"info.id": {"$in": task_ids}}, {"behavior.processes.calls": 1})

        for task in tasks or []:
            for process in task.get("behavior", {}).get("processes", []) or []:
                if process.get("calls"):
                    mongo_delete_many("calls", {"_id": {"$in": process["calls"]}})
            analyses_tmp.append(task["_id"])

        if analyses_tmp:
            mongo_delete_many({"_id": {"$in": analyses_tmp}})
    except Exception as e:
        log.error(e, exc_info=True)
