import logging
import itertools
from typing import List, Optional, Sequence

try:
    # Native PyMongo Async support (Requires pymongo >= 4.9)
    from pymongo.asynchronous import AsyncMongoClient
    from bson import ObjectId
    HAVE_PYMONGO_ASYNC = True
except ImportError:
    HAVE_PYMONGO_ASYNC = False

from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)
repconf = Config("reporting")
mdb_name = repconf.mongodb.get("db", "cuckoo")

# Async Client Singleton
_async_client = None
_async_db = None

def get_async_db():
    """Returns the native async PyMongo database instance, initializing it if necessary."""
    global _async_client, _async_db

    if not HAVE_PYMONGO_ASYNC:
        raise ImportError("Native PyMongo Async API is not available. Please upgrade pymongo: pip install 'pymongo>=4.9'")

    if _async_db is None:
        try:
            _async_client = AsyncMongoClient(
                host=repconf.mongodb.get("host", "127.0.0.1"),
                port=repconf.mongodb.get("port", 27017),
                username=repconf.mongodb.get("username"),
                password=repconf.mongodb.get("password"),
                authSource=repconf.mongodb.get("authsource", "cuckoo"),
                tlsCAFile=repconf.mongodb.get("tlscafile", None),
                serverSelectionTimeoutMS=5000,
            )
            _async_db = _async_client[mdb_name]
            log.info("Native Async MongoDB connection initialized.")
        except Exception as e:
            log.error("Failed to initialize Native Async MongoDB connection: %s", e)
            raise

    return _async_db

async def mongo_find_one_async(collection: str, query: dict, projection: dict = None, sort: list = None) -> Optional[dict]:
    """Async wrapper for find_one."""
    db = get_async_db()
    if sort is None:
        sort = [("_id", -1)]
    try:
        return await db[collection].find_one(query, projection, sort=sort)
    except Exception as e:
        log.error("Error in mongo_find_one_async: %s", e)
        return None

async def mongo_find_async(collection: str, query: dict, projection: dict = None, sort: list = None, limit: int = 0) -> List[dict]:
    """Async wrapper for find (returns a list)."""
    db = get_async_db()
    if sort is None:
        sort = [("_id", -1)]
    try:
        cursor = db[collection].find(query, projection, sort=sort)
        if limit > 0:
            cursor.limit(limit)
        return await cursor.to_list(length=limit if limit else None)
    except Exception as e:
        log.error("Error in mongo_find_async: %s", e)
        return []

async def mongo_count_async(collection: str, query: dict) -> int:
    """Async wrapper for count_documents."""
    db = get_async_db()
    try:
        return await db[collection].count_documents(query)
    except Exception as e:
        log.error("Error in mongo_count_async: %s", e)
        return 0

async def mongo_insert_one_async(collection: str, doc: dict):
    """Async wrapper for insert_one."""
    db = get_async_db()
    try:
        return await db[collection].insert_one(doc)
    except Exception as e:
        log.error("Error in mongo_insert_one_async: %s", e)
        return None

async def mongo_bulk_write_async(collection: str, requests: list, **kwargs):
    """Async wrapper for bulk_write."""
    db = get_async_db()
    try:
        return await db[collection].bulk_write(requests, **kwargs)
    except Exception as e:
        log.error("Error in mongo_bulk_write_async: %s", e)
        return None

async def mongo_create_index_async(collection: str, index, background: bool = True, name: str = None):
    """Async wrapper for create_index."""
    db = get_async_db()
    try:
        if name:
            await db[collection].create_index(index, background=background, name=name)
        else:
            await db[collection].create_index(index, background=background)
    except Exception as e:
        log.error("Error in mongo_create_index_async: %s", e)

async def mongo_delete_one_async(collection: str, query: dict):
    """Async wrapper for delete_one."""
    db = get_async_db()
    try:
        return await db[collection].delete_one(query)
    except Exception as e:
        log.error("Error in mongo_delete_one_async: %s", e)
        return None

async def mongo_delete_many_async(collection: str, query: dict):
    """Async wrapper for delete_many."""
    db = get_async_db()
    try:
        return await db[collection].delete_many(query)
    except Exception as e:
        log.error("Error in mongo_delete_many_async: %s", e)
        return None

async def mongo_update_many_async(collection: str, query: dict, update: dict):
    """Async wrapper for update_many."""
    db = get_async_db()
    try:
        return await db[collection].update_many(query, update)
    except Exception as e:
        log.error("Error in mongo_update_many_async: %s", e)
        return None

async def mongo_update_one_async(collection: str, query: dict, update: dict, upsert: bool = False, bypass_document_validation: bool = False):
    """Async wrapper for update_one."""
    db = get_async_db()
    try:
        return await db[collection].update_one(query, update, upsert=upsert, bypass_document_validation=bypass_document_validation)
    except Exception as e:
        log.error("Error in mongo_update_one_async: %s", e)
        return None

async def mongo_aggregate_async(collection: str, pipeline: list):
    """Async wrapper for aggregate."""
    db = get_async_db()
    try:
        cursor = db[collection].aggregate(pipeline)
        return await cursor.to_list(length=None)
    except Exception as e:
        log.error("Error in mongo_aggregate_async: %s", e)
        return []

async def mongo_collection_names_async() -> list:
    """Async wrapper for list_collection_names."""
    db = get_async_db()
    try:
        return await db.list_collection_names()
    except Exception as e:
        log.error("Error in mongo_collection_names_async: %s", e)
        return []

async def mongo_find_one_and_update_async(collection: str, query: dict, update: dict, projection: dict = None):
    """Async wrapper for find_one_and_update."""
    db = get_async_db()
    if projection is None:
        projection = {"_id": 1}
    try:
        return await db[collection].find_one_and_update(query, update, projection=projection)
    except Exception as e:
        log.error("Error in mongo_find_one_and_update_async: %s", e)
        return None

async def mongo_drop_database_async(database: str):
    """Async wrapper for drop_database."""
    # This requires access to the client, not just the default db
    # We expose the client via a helper or access the global if needed,
    # but strictly speaking drop_database is a method on the Client, not the Database object usually.
    # However, pymongo Client.drop_database(name) exists.
    # Our get_async_db() returns a Database object. We need the client.

    global _async_client
    if _async_client is None:
        get_async_db() # ensure init

    try:
        if _async_client:
            await _async_client.drop_database(database)
    except Exception as e:
        log.error("Error in mongo_drop_database_async: %s", e)

# Complex helpers (ported from mongodb.py logic)

async def mongo_delete_calls_async(task_ids: Sequence[int] | None) -> None:
    """Async version of mongo_delete_calls."""
    log.info("attempting to delete calls for %d tasks (async)", len(task_ids) if task_ids else 0)

    query = {"info.id": {"$in": list(task_ids)}}
    projection = {"behavior.processes.calls": 1}
    tasks = await mongo_find_async("analysis", query, projection=projection)

    if not tasks:
        return

    delete_target_ids = []

    def get_call_ids_from_task(task: dict) -> list:
        processes = task.get("behavior", {}).get("processes", [])
        calls = [proc.get("calls", []) for proc in processes]
        return list(itertools.chain.from_iterable(calls))

    for task in tasks:
        delete_target_ids.extend(get_call_ids_from_task(task))

    delete_target_ids = list(set(delete_target_ids))
    chunk_size = 1000
    for idx in range(0, len(delete_target_ids), chunk_size):
        await mongo_delete_many_async("calls", {"_id": {"$in": delete_target_ids[idx : idx + chunk_size]}})

async def mongo_delete_data_async(task_ids: int | Sequence[int]) -> None:
    """Async version of mongo_delete_data."""
    try:
        if isinstance(task_ids, int):
            task_ids = [task_ids]

        if task_ids:
            await mongo_delete_calls_async(task_ids=task_ids)
            await mongo_delete_many_async("analysis", {"info.id": {"$in": list(task_ids)}})
            # Hooks are skipped for async simplicity for now, or can be added if needed
    except Exception as e:
        log.exception(e)

async def mongo_delete_calls_by_task_id_in_range_async(*, range_start: int = 0, range_end: int = 0) -> None:
    """Async version of mongo_delete_calls_by_task_id_in_range."""
    task_id_query = {}
    if range_start > 0:
        task_id_query["$gte"] = range_start
    if range_end > 0:
        task_id_query["$lt"] = range_end
    if task_id_query:
        await mongo_delete_many_async("calls", {"task_id": task_id_query})

async def mongo_delete_data_range_async(*, range_start: int = 0, range_end: int = 0) -> None:
    """Async version of mongo_delete_data_range."""
    INFO_ID = "info.id"
    try:
        info_id_query = {}
        if range_start > 0:
            info_id_query["$gte"] = range_start
        if range_end > 0:
            info_id_query["$lt"] = range_end
        if info_id_query:
            await mongo_delete_calls_by_task_id_in_range_async(range_start=range_start, range_end=range_end)
            await mongo_delete_many_async("analysis", {INFO_ID: info_id_query})
    except Exception as e:
        log.exception(e)
