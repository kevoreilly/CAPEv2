from __future__ import absolute_import
import os
from lib.cuckoo.common.constants import CUCKOO_ROOT

_root = CUCKOO_ROOT
try:
    import pwd

    HAVE_PWD = True
except ImportError:
    HAVE_PWD = False


def getuser():
    if HAVE_PWD:
        return pwd.getpwuid(os.getuid())[0]
    return ""


def cwd(*args, **kwargs):
    """Return absolute path to this file in the Cuckoo Working Directory or
    optionally - when private=True has been passed along - to our private
    Cuckoo Working Directory which is not configurable."""
    if kwargs.get("root"):
        return _root
    elif kwargs.get("analysis"):
        return os.path.join(_root, "storage", "analyses", "%s" % kwargs["analysis"], *args)
    elif kwargs:
        raise RuntimeError("Invalid arguments provided to cwd(): %r %r" % (args, kwargs))
    else:
        return os.path.join(_root, *args)
