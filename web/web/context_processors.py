from contextlib import suppress
from functools import lru_cache

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_VERSION
from lib.cuckoo.common.utils import get_running_commit

web_cfg = Config("web")


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("yes", "true", "on", "1")
    return bool(value)


@lru_cache(maxsize=1)
def _get_cached_running_commit() -> str:
    with suppress(Exception):
        return get_running_commit()
    return ""


def cape_version(request):
    """Expose CAPE version and running git commit hash when [display_version] is enabled."""
    display_cfg = getattr(web_cfg, "display_version", None)
    enabled = _as_bool(display_cfg.get("enabled", False)) if display_cfg is not None else False
    if not enabled:
        return {
            "display_cape_version": False,
            "cape_version": "",
            "cape_commit": "",
        }

    return {
        "display_cape_version": True,
        "cape_version": CUCKOO_VERSION,
        "cape_commit": _get_cached_running_commit(),
    }
