import os
import sys

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.core.database import Database

repconf = Config("reporting")
if len(sys.argv) == 2:
    db = Database()
    paths = db.sample_path_by_hash(sys.argv[1])
    if paths is not None:
        paths = [path for path in paths if path_exists(path)]
        if paths:
            print(("Found by db.sample_path_by_hash: {}".format(sys.argv[1])))
            print("\n".join(paths))
else:
    print("provide hash to search")
