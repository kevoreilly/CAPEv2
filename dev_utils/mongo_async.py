import logging
from typing import Any, List, Optional

try:
    from motor.motor_asyncio import AsyncIOMotorClient
    HAVE_MOTOR = True
except ImportError:
    HAVE_MOTOR = False

from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)
repconf = Config("reporting")
mdb_name = repconf.mongodb.get("db", "cuckoo")

# Async Client Singleton
_async_client = None
_async_db = None

def get_async_db():
    """Returns the async Motor database instance, initializing it if necessary."""
    global _async_client, _async_db
    
    if not HAVE_MOTOR:
        raise ImportError("Motor is not installed. Please install it with: pip install motor")

    if _async_db is None:
        try:
            _async_client = AsyncIOMotorClient(
                host=repconf.mongodb.get("host", "127.0.0.1"),
                port=repconf.mongodb.get("port", 27017),
                username=repconf.mongodb.get("username"),
                password=repconf.mongodb.get("password"),
                authSource=repconf.mongodb.get("authsource", "cuckoo"),
                tlsCAFile=repconf.mongodb.get("tlscafile", None),
                serverSelectionTimeoutMS=5000,  # Fail fast if DB is down
            )
            _async_db = _async_client[mdb_name]
            log.info("Async MongoDB connection initialized.")
        except Exception as e:
            log.error("Failed to initialize Async MongoDB connection: %s", e)
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
        
        # Be careful with large limits without projection!
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
