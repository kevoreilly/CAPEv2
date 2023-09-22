import itertools
import logging

from pymongo import UpdateOne

from dev_utils.mongodb import (
    mongo_bulk_write,
    mongo_delete_data,
    mongo_delete_many,
    mongo_find,
    mongo_find_one,
    mongo_hook,
    mongo_insert_one,
    mongo_update_many,
    mongo_update_one,
)

log = logging.getLogger(__name__)

FILES_COLL = "files"
FILE_KEY = "sha256"
TASK_IDS_KEY = "_task_ids"


def normalize_file(file_dict, task_id):
    """Pull out the detonation-independent attributes of the given file and
    return an UpdateOne object usable by bulk_write to upsert a
    document into the FILES_COLL collection with its _id set to the FILE_KEY of
    the file. The given file_dict is updated in place to remove those
    attributes and add a 'file_ref' key containing the FILE_KEY that can be
    used as a lookup in the FILES_COLL collection.
    If the file has already been "normalized," then it is not modified and
    None is returned.
    """
    if "file_ref" in file_dict:
        # This has already been normalized.
        return
    key = file_dict.get(FILE_KEY, None)
    if not key:
        return
    static_fields = (
        # hashes
        "crc32",
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "sha3_384",
        "ssdeep",
        "tlsh",
        "rh_hash",
        # other metadata & static analysis fields
        "size",
        "pe",
        "ep_bytes",
        "entrypoint",
        "data",
        "strings",
    )
    new_dict = {}
    for fld in static_fields:
        try:
            new_dict[fld] = file_dict.pop(fld)
        except KeyError:
            pass

    new_dict["_id"] = key
    file_dict["file_ref"] = key
    return UpdateOne({"_id": key}, {"$set": new_dict, "$addToSet": {TASK_IDS_KEY: task_id}}, upsert=True, hint=[("_id", 1)])


@mongo_hook((mongo_insert_one, mongo_update_one), "analysis")
def normalize_files(report):
    """Take the detonation-independent file data from various parts of
    the report and extract them out to a separate collection, keeping a
    reference to it (along with the detonation-dependent fields) in the
    report.
    """
    requests = []
    for file_dict in collect_file_dicts(report):
        request = normalize_file(file_dict, report["info"]["id"])
        if request:
            requests.append(request)
    if requests:
        mongo_bulk_write(FILES_COLL, requests, ordered=False)

    return report


@mongo_hook(mongo_find_one, "analysis")
def denormalize_files(report):
    """Pull the file info from the FILES_COLL collection in to associated parts of
    the report.
    """
    file_dicts = tuple(collect_file_dicts(report))
    if not file_dicts:
        # This is likely a partial report (like for an ajax request of a specific
        # part of the report) that does not include any file information.
        return report

    if "file_ref" not in file_dicts[0]:
        # This analysis uses the old-style of storing file information.
        # It includes the static file info in the analysis document
        # instead of in the FILES_COLL collection.
        return report

    file_refs = {file_dict["file_ref"] for file_dict in file_dicts}
    file_docs = {}
    for file_doc in mongo_find(FILES_COLL, {"_id": {"$in": list(file_refs)}}, {TASK_IDS_KEY: 0}):
        file_docs[file_doc.pop("_id")] = file_doc
    for file_dict in file_dicts:
        if file_dict["file_ref"] not in file_docs:
            log.warning("Failed to find %s in %s collection.", FILES_COLL, file_dict["file_ref"])
            continue
        file_doc = file_docs[file_dict.pop("file_ref")]
        file_dict.update(file_doc)

    return report


@mongo_hook(mongo_delete_data, "analysis")
def remove_task_references_from_files(task_ids):
    """Remove the given task_ids from the TASK_IDS_KEY field on "files"
    documents that were referenced by those tasks that are being deleted.
    """
    mongo_update_many(
        FILES_COLL,
        {TASK_IDS_KEY: {"$elemMatch": {"$in": task_ids}}},
        {"$pullAll": {TASK_IDS_KEY: task_ids}},
    )


def delete_unused_file_docs():
    """Delete entries in the FILES_COLL collection that are no longer
    referenced by any analysis tasks. This should typically be invoked
    via utils/cleaners.py in a cron job.
    """
    return mongo_delete_many(FILES_COLL, {TASK_IDS_KEY: {"$size": 0}})


def collect_file_dicts(report) -> itertools.chain:
    """Return an iterable containing all of the candidates for files
    from various parts of the report to be normalized.
    """
    file_dicts = []
    target_file = report.get("target", {}).get("file", None)
    if target_file:
        file_dicts.append([target_file])
    file_dicts.append(report.get("dropped", None) or [])
    file_dicts.append(report.get("CAPE", {}).get("payloads", None) or [])
    file_dicts.append(report.get("procdump", None) or [])
    return itertools.chain.from_iterable(file_dicts)
