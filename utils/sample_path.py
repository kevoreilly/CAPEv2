import argparse
import os
import sys

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.core.database import Database, init_database

repconf = Config("reporting")

if "__main__" == __name__:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash", help="Hash to lookup", default=None, action="store", required=False)
    parser.add_argument("--id", help="Get hash by sample_id from task", default=None, action="store", required=False)
    args = parser.parse_args()

    init_database()
    paths = Database().sample_path_by_hash(sample_hash=args.hash, task_id=args.id)
    if paths:
        paths = [path for path in paths if path_exists(path)]
        if paths:
            print("\n".join(paths))
