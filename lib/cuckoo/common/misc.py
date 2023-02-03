import os

from lib.cuckoo.common.constants import CUCKOO_ROOT

try:
    import pwd

    HAVE_PWD = True
except ImportError:
    HAVE_PWD = False

_root = CUCKOO_ROOT


def getuser() -> str:
    return pwd.getpwuid(os.getuid())[0] if HAVE_PWD else ""


def cwd(*args, **kwargs):
    """Return absolute path to this file in the Cuckoo Working Directory or
    optionally - when private=True has been passed along - to our private
    Cuckoo Working Directory which is not configurable."""
    if kwargs.get("root"):
        return _root
    elif kwargs.get("analysis"):
        return os.path.join(_root, "storage", "analyses", str(kwargs["analysis"]), *args)
    elif kwargs:
        raise RuntimeError(f"Invalid arguments provided to cwd(): {args} {kwargs}")
    else:
        return os.path.join(_root, *args)
