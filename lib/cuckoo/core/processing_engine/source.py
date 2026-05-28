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
        (in-flight). Tasks are expunged so they are safe to use after the txn."""
        if limit <= 0:
            return []
        with self.db.session.begin_nested():
            tasks = self.db.list_tasks(status=self._status, limit=limit, order_by=Task.completed_on.asc())
            self.db.session.expunge_all()
        return [t for t in tasks if t.id not in exclude_ids]

    def mark_failed(self, task_id):
        with self.db.session.begin_nested():
            self.db.set_status(task_id, TASK_FAILED_PROCESSING)
