import functools
import logging
import time
from typing import Callable, Iterable

from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)
repconf = Config("reporting")

mdb = repconf.mongodb.get("db", "cuckoo")


if repconf.mongodb.enabled:
    from pymongo import MongoClient, version_tuple
    from pymongo.errors import AutoReconnect, ConnectionFailure, OperationFailure, ServerSelectionTimeoutError

    if version_tuple[0] < 4:
        log.warning("You using old version of PyMongo, upgrade: pip3 install pymongo -U")

MAX_AUTO_RECONNECT_ATTEMPTS = 5


def graceful_auto_reconnect(mongo_op_func: Callable):
    """Gracefully handle a reconnection event."""

    @functools.wraps(mongo_op_func)
    def wrapper(*args, **kwargs):
        for attempt in range(MAX_AUTO_RECONNECT_ATTEMPTS):
            try:
                return mongo_op_func(*args, **kwargs)
            except AutoReconnect as e:
                wait_t = 0.5 * pow(2, attempt)  # exponential back off
                logging.warning("PyMongo auto-reconnecting...%s. Waiting %.1f seconds", e, wait_t)
                time.sleep(wait_t)

    return wrapper


def connect_to_mongo() -> MongoClient:
    try:
        return MongoClient(
            host=repconf.mongodb.get("host", "127.0.0.1"),
            port=repconf.mongodb.get("port", 27017),
            username=repconf.mongodb.get("username"),
            password=repconf.mongodb.get("password"),
            authSource=repconf.mongodb.get("authsource", "cuckoo"),
            tlsCAFile=repconf.mongodb.get("tlscafile", None),
            connect=False,
        )
    except (ConnectionFailure, ServerSelectionTimeoutError):
        log.error("Cannot connect to MongoDB")
    except Exception as e:
        log.warning("Unable to connect to MongoDB database: %s, %s", mdb, e)


# code.interact(local=dict(locals(), **globals()))
# q = results_db.analysis.find({"info.id": 26}, {"memory": 1})
# https://pymongo.readthedocs.io/en/stable/changelog.html

conn = connect_to_mongo()
results_db = conn[mdb]


@graceful_auto_reconnect
def mongo_create_index(collection: str, index, background: bool = True, name: str = False):
    if name:
        getattr(results_db, collection).create_index(index, background=background, name=name)
    else:
        getattr(results_db, collection).create_index(index, background=background)


@graceful_auto_reconnect
def mongo_insert_one(collection: str, query):
    return getattr(results_db, collection).insert_one(query)


@graceful_auto_reconnect
def mongo_find(collection: str, query, projection=False, sort=None):
    if sort is None:
        sort = [("_id", -1)]
    if projection:
        return getattr(results_db, collection).find(query, projection, sort=sort)
    return getattr(results_db, collection).find(query, sort=sort)


@graceful_auto_reconnect
def mongo_find_one(collection: str, query, projection=False, sort=None):
    if sort is None:
        sort = [("_id", -1)]
    if projection:
        return getattr(results_db, collection).find_one(query, projection, sort=sort)
    return getattr(results_db, collection).find_one(query, sort=sort)


@graceful_auto_reconnect
def mongo_delete_one(collection: str, query):
    return getattr(results_db, collection).delete_one(query)


@graceful_auto_reconnect
def mongo_delete_many(collection: str, query):
    return getattr(results_db, collection).delete_many(query)


@graceful_auto_reconnect
def mongo_update(collection: str, query, projection):
    return getattr(results_db, collection).update(query, projection)


@graceful_auto_reconnect
def mongo_update_one(collection: str, query, projection, bypass_document_validation: bool = False):
    return getattr(results_db, collection).update_one(query, projection, bypass_document_validation=bypass_document_validation)


@graceful_auto_reconnect
def mongo_aggregate(collection: str, query):
    return getattr(results_db, collection).aggregate(query)


@graceful_auto_reconnect
def mongo_collection_names() -> list:
    return results_db.list_collection_names()


@graceful_auto_reconnect
def mongo_find_one_and_update(collection, query, update, projection=None):
    if projection is None:
        projection = {"_id": 1}
    return getattr(results_db, collection).find_one_and_update(query, update, projection)


@graceful_auto_reconnect
def mongo_drop_database(database: str):
    conn.drop_database(database)


def mongo_delete_data(task_ids: Iterable[int]):  #  | int
    try:
        if isinstance(task_ids, int):
            task_ids = [task_ids]

        analyses_tmp = []
        tasks = mongo_find("analysis", {"info.id": {"$in": task_ids}}, {"behavior.processes.calls": 1})

        for task in tasks or []:
            for process in task.get("behavior", {}).get("processes", []):
                if process.get("calls"):
                    mongo_delete_many("calls", {"_id": {"$in": process["calls"]}})
            analyses_tmp.append(task["_id"])

        if analyses_tmp:
            mongo_delete_many("analysis", {"_id": {"$in": analyses_tmp}})
    except Exception as e:
        log.error(e, exc_info=True)


def mongo_is_cluster():
    # This is only useful at the moment for clean to prevent destruction of cluster database
    try:
        conn.admin.command("listShards")
        return True
    except OperationFailure:
        return False
