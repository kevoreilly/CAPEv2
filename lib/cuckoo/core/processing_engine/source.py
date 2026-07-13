"""Shared task source for processing engines: pulls tasks needing processing
from the DB and writes terminal status. Engines differ in how they *run* tasks,
not in how they pull them."""
import logging

from lib.cuckoo.core.data.task import TASK_COMPLETED, TASK_FAILED_PROCESSING, Task

log = logging.getLogger(__name__)


class TaskSource:
    def __init__(self, db, failed_processing=False):
        self.db = db
        self._status = TASK_FAILED_PROCESSING if failed_processing else TASK_COMPLETED

    def fetch(self, limit, exclude_ids):
        """Return up to `limit` tasks needing processing, excluding `exclude_ids`
        (in-flight). Tasks are expunged so they are safe to use after the txn.

        The DB query fetches `limit + len(exclude_ids)` rows so that, after
        dropping the in-flight ids, up to `limit` eligible tasks remain. Querying
        only `limit` would starve workers: if the oldest tasks are all in-flight
        they'd be filtered out, returning fewer (or zero) tasks while other
        eligible work waits. The result is sliced back to `limit`."""
        if limit <= 0:
            return []
        db_limit = limit + len(exclude_ids)
        with self.db.session.begin():
            tasks = self.db.list_tasks(status=self._status, limit=db_limit, order_by=Task.completed_on.asc())
            self.db.session.expunge_all()
        return [t for t in tasks if t.id not in exclude_ids][:limit]

    def mark_failed(self, task_id):
        # Always writes TASK_FAILED_PROCESSING regardless of which status this
        # source polls (the `failed_processing` constructor flag controls reads).
        with self.db.session.begin():
            self.db.set_status(task_id, TASK_FAILED_PROCESSING)
