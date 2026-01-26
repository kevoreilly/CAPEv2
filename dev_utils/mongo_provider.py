import logging
import os
from asgiref.sync import sync_to_async
from django.conf import settings

# Default configuration
USE_ASYNC_MONGO = getattr(settings, "USE_ASYNC_MONGO", False)

log = logging.getLogger(__name__)

# Fallback: Sync Implementation (wrapped)
from dev_utils import mongodb as sync_mongo

# Try Async Implementation
try:
    from dev_utils import mongo_async as async_mongo
    HAVE_ASYNC_IMPL = async_mongo.HAVE_PYMONGO_ASYNC
except ImportError:
    HAVE_ASYNC_IMPL = False

if USE_ASYNC_MONGO and HAVE_ASYNC_IMPL:
    log.info("Using Native Async MongoDB Provider")
    
    # Direct alias to async functions
    mongo_find_one = async_mongo.mongo_find_one_async
    mongo_find = async_mongo.mongo_find_async
    mongo_insert_one = async_mongo.mongo_insert_one_async
    mongo_update_one = async_mongo.mongo_update_one_async
    mongo_update_many = async_mongo.mongo_update_many_async
    mongo_delete_one = async_mongo.mongo_delete_one_async
    mongo_delete_many = async_mongo.mongo_delete_many_async
    mongo_aggregate = async_mongo.mongo_aggregate_async
    mongo_count = async_mongo.mongo_count_async
    mongo_find_one_and_update = async_mongo.mongo_find_one_and_update_async
    mongo_bulk_write = async_mongo.mongo_bulk_write_async
    mongo_create_index = async_mongo.mongo_create_index_async
    
    # Complex helpers
    mongo_delete_data = async_mongo.mongo_delete_data_async
    mongo_delete_data_range = async_mongo.mongo_delete_data_range_async

else:
    if USE_ASYNC_MONGO:
        log.warning("Async MongoDB requested but dependencies missing. Falling back to Sync wrapper.")
    else:
        log.info("Using Sync-to-Async MongoDB Wrapper")

    # Wrap synchronous functions to make them awaitable
    mongo_find_one = sync_to_async(sync_mongo.mongo_find_one)
    mongo_find = sync_to_async(sync_mongo.mongo_find)
    mongo_insert_one = sync_to_async(sync_mongo.mongo_insert_one)
    mongo_update_one = sync_to_async(sync_mongo.mongo_update_one)
    mongo_update_many = sync_to_async(sync_mongo.mongo_update_many)
    mongo_delete_one = sync_to_async(sync_mongo.mongo_delete_one)
    mongo_delete_many = sync_to_async(sync_mongo.mongo_delete_many)
    mongo_aggregate = sync_to_async(sync_mongo.mongo_aggregate)
    
    # Helper for count (mongodb.py doesn't have a direct count wrapper usually, 
    # but we can wrap a lambda or access the db directly if needed.
    # mongodb.py usually returns the result directly from find if it was a cursor but it returns list.
    # Let's check how count is usually done. 
    # Usually: results_db.collection.count_documents(query)
    # We will wrap a custom lambda for count since mongodb.py might not export it explicitly.
    def _sync_count(collection, query):
        return getattr(sync_mongo.results_db, collection).count_documents(query)
    
    mongo_count = sync_to_async(_sync_count)
    
    mongo_find_one_and_update = sync_to_async(sync_mongo.mongo_find_one_and_update)
    mongo_bulk_write = sync_to_async(sync_mongo.mongo_bulk_write)
    mongo_create_index = sync_to_async(sync_mongo.mongo_create_index)
    
    # Complex helpers
    mongo_delete_data = sync_to_async(sync_mongo.mongo_delete_data)
    mongo_delete_data_range = sync_to_async(sync_mongo.mongo_delete_data_range)
