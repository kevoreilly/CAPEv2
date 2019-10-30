from __future__ import absolute_import
from __future__ import print_function
import sys
import os
from queue import Queue
from sqlalchemy import desc
import threading
CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

lock = threading.Lock()
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database, TASK_PENDING, Sample, Task
from lib.cuckoo.common.dist_db import create_session
from lib.cuckoo.common.dist_db import Task as DTask
reporting_conf = Config("reporting")

main_db = Database()
session = main_db.Session()
dist_session = create_session(reporting_conf.distributed.db, echo=False)
dist_db = dist_session()

duplicated = session.query(Sample, Task).join(Task).filter(Sample.id==Task.sample_id, Task.status=="pending").order_by(Sample.sha256)
hash_dict = dict()
q = Queue()

def dedupme():
    while not q.empty:
        sha256 = q.get()
        # keep an task for that hash
        for id, file in hash_dict[sha256][1:]:
            try:
                if os.path.exists(file):
                    try:
                        os.remove(file)
                    except Exception as e:
                        print(e)

                main_db.delete_task(id)
                # clean dist_db
                dist_task = dist_db.query(Task).filter(DTask.main_task.id==id).first()
                if dist_task:
                    dist_db.delete(dist_task.id)
            except Exception as e:
                print(e)

        q.task_done()

for sample, task in duplicated:
    try:
        # hash -> [[id, file]]
        hash_dict.setdefault(sample.sha256, list())
        hash_dict[sample.sha256].append((task.id, task.target))
    except UnicodeDecodeError:
        pass

for sha256 in hash_dict:
    q.put(sha256)

threads = list()
for num in range(10):
    thread = threading.Thread(target = dedupme, args=())
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()
