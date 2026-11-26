"""Shellcode framework identifiers and extractors, one module per generator layout.

Every .py module in this folder is a framework: the ones shipped with CAPE and any you drop in
(for example a loader you track). They are discovered once per process, on first use, and run in
PRIORITY order over the raw bytes of every buffer the static shellcode check analyses. See
README.md for the module contract.
"""

import importlib
import logging
import pkgutil
from typing import Any, Callable, NamedTuple

log = logging.getLogger(__name__)

PACKAGES = [__name__]  # where framework modules are discovered (tests add a temporary package)
DEFAULT_PRIORITY = 100
CONFIDENCES = ("identified", "possible")
MAX_POSSIBLE = 4  # 'possible' matches reported when nothing is identified
_NOT_MODULES = {"api"}


class Framework(NamedTuple):
    name: str
    family: str
    priority: int
    identify: Callable[[bytes], Any]
    module: str


_registry = None


def _discover(package):
    try:
        pkg = importlib.import_module(package)
    except ImportError as e:
        log.error("shellcode frameworks: package %s not loaded: %s", package, e)
        return []
    found = []
    for info in sorted(pkgutil.iter_modules(getattr(pkg, "__path__", [])), key=lambda i: i.name):
        if info.ispkg or info.name.startswith("_") or info.name in _NOT_MODULES:
            continue
        module = f"{package}.{info.name}"
        try:
            mod = importlib.import_module(module)
        except Exception as e:
            log.error("shellcode framework %s not loaded: %s", module, e)
            continue
        name, identify = getattr(mod, "NAME", None), getattr(mod, "identify", None)
        priority = getattr(mod, "PRIORITY", DEFAULT_PRIORITY)
        if not isinstance(name, str) or not name.strip() or not callable(identify) or not isinstance(priority, int):
            log.error("shellcode framework %s not loaded: needs NAME (str), identify(data) and an int PRIORITY", module)
            continue
        family = getattr(mod, "FAMILY", None) or name
        found.append(Framework(name, family, priority, identify, module))
    return found


def frameworks():
    """Loaded framework modules in run order (lowest PRIORITY first, then NAME)."""
    global _registry
    if _registry is None:
        loaded = {}
        for package in PACKAGES:
            for fw in _discover(package):
                if fw.name in loaded:
                    log.error(
                        "shellcode framework %s not loaded: NAME %r is already used by %s",
                        fw.module,
                        fw.name,
                        loaded[fw.name].module,
                    )
                    continue
                loaded[fw.name] = fw
        _registry = sorted(loaded.values(), key=lambda f: (f.priority, f.name))
    return _registry


def reset():
    """Forget the loaded modules (tests; a running CAPE picks up added modules on restart)."""
    global _registry
    _registry = None


def family(name):
    """CAPE detection family for an identified framework (its FAMILY, default its NAME)."""
    return next((f.family for f in frameworks() if f.name == name), name)


def _normalise(fw, res):
    """Check a module's result against the contract and fill optional fields; None if unusable."""
    if not isinstance(res, dict) or res.get("confidence") not in CONFIDENCES:
        log.error("shellcode framework %s returned an invalid result (needs a dict with confidence in %s)", fw.module, CONFIDENCES)
        return None
    res["name"] = fw.name
    res.setdefault("arch", None)
    for key, default in (("evidence", list), ("details", dict), ("regions", list), ("iocs", dict)):
        if not isinstance(res.get(key), default):
            res[key] = default()
    for region in res["regions"]:
        region.setdefault("framework", fw.name)
        for key in ("status", "source", "result_type", "result"):
            region.setdefault(key, "structural" if key == "status" else "")
        region.setdefault("entropy", None)
        region.setdefault("decoded_entropy", None)
    payload = res.get("_payload")
    if payload is not None and not (
        isinstance(payload, dict) and callable(payload.get("extract")) and isinstance(payload.get("offset"), int)
    ):
        log.error("shellcode framework %s returned an invalid _payload (needs extract() and an int offset)", fw.module)
        res.pop("_payload")
    elif payload is not None:
        payload.setdefault("description", f"{fw.name} payload")
    return res


def identify(data):
    """Run every framework module over the bytes: [the first identified match], else up to
    MAX_POSSIBLE 'possible' matches, else []. A module that raises is logged and skipped."""
    possible = []
    for fw in frameworks():
        try:
            res = fw.identify(data)
        except Exception as e:
            log.warning("shellcode framework %s failed: %s", fw.module, e)
            continue
        if not res:
            continue
        res = _normalise(fw, res)
        if res is None:
            continue
        if res["confidence"] == "identified":
            return [res]  # one generator writes the outer layout
        if len(possible) < MAX_POSSIBLE:
            possible.append(res)
    return possible
