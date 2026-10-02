# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
"""Google Magika deep-learning content type identification.

https://github.com/google/magika

Magika is a content type detector built on a small ONNX model rather than
on byte signatures. It complements -- it does not replace -- libmagic:

  * libmagic is authoritative when a real magic signature is present
    (`MZ`, `\\x7fELF`, `%PDF`, OLE CFB, ...). It is deterministic and it is
    what the rest of CAPE substring-matches against ("PE32", "MS Windows
    shortcut", "Java Jar", ...).
  * Magika is useful exactly where libmagic returns `data` /
    `application/octet-stream`: script fragments, decoded/deobfuscated
    buffers, config blobs, shellcode-adjacent text, dropped files with no
    header, and the endless supply of headerless CAPE payloads.

So this integration runs *below* the existing magic determination and is
purely additive: it stores a `magika` block next to `type` and never
modifies `type` itself. That is deliberate --

  * the raw libmagic verdict stays visible and unaltered, which is what
    every existing substring match in CAPE (and every analyst) relies on;
  * keeping the two verdicts separate is itself a detection surface.
    libmagic saying "ASCII text" while magika says `pebin`, or a `.jpg`
    whose magika label is `powershell`, is a signal you can only see if
    nothing has collapsed the two into one string.

Enable in: processing.conf -> [magika] -> enabled = yes
Requires: poetry run pip install -U magika
"""

import contextlib
import logging
import os
import threading
from importlib import import_module
from pathlib import Path

from cachetools import TTLCache

from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)

processing_conf = Config("processing")

# A stale conf tree (no [magika] section anywhere, e.g. a partially updated
# deployment) must degrade to "disabled", not to an AttributeError at import
# time in a module that objects.py imports unconditionally.
_magika_conf = getattr(processing_conf, "magika", None)


def _conf(key, default):
    if _magika_conf is None:
        return default
    value = getattr(_magika_conf, key, default)
    return default if value is None else value


# ConfigParser-backed booleans/ints are already coerced by CAPE's Config wrapper.
MAGIKA_ENABLED = bool(_conf("enabled", False))
MAGIKA_MODEL_DIR = _conf("model_dir", "") or ""
MAGIKA_PREDICTION_MODE = _conf("prediction_mode", "high_confidence") or "high_confidence"

# Display-only threshold: results below it are still stored and shown, just
# flagged so a weak prediction is not mistaken for a confident one.
try:
    MAGIKA_MIN_SCORE = float(_conf("min_score", 0.5))
except (TypeError, ValueError):
    MAGIKA_MIN_SCORE = 0.5

try:
    # MB. 0 disables the guard.
    MAGIKA_MAX_FILE_SIZE = int(_conf("max_file_size", 100))
except (TypeError, ValueError):
    MAGIKA_MAX_FILE_SIZE = 100

HAVE_MAGIKA = False
_magika_module = None

if MAGIKA_ENABLED:
    try:
        # Absolute import: this file is `lib.cuckoo.common.integrations.magika`,
        # the dependency is top-level `magika`. Python 3 has no implicit
        # relative imports so these do not collide -- but we assert on the
        # public symbol anyway so a shadowed import degrades to "disabled"
        # instead of blowing up mid-analysis.
        _magika_module = import_module("magika")
        if not hasattr(_magika_module, "Magika"):
            raise ImportError("imported 'magika' does not expose Magika (module shadowing?)")
        HAVE_MAGIKA = True
    except ImportError as e:
        log.warning("Magika is enabled in processing.conf but unavailable: %s. Install with: poetry run pip install -U magika", e)

# The ONNX session is expensive to build (~0.5-1s) and cheap to reuse
# (~1-5ms/file), so it is a lazily-built per-process singleton. Workers are
# long-lived, hence the lock rather than a module-level constructor.
_MODEL_LOCK = threading.Lock()
_MAGIKA_INSTANCE = None

# Per-task result cache, same lifecycle contract as the clamav one: keyed by
# absolute path, TTL-bounded so a long-lived worker cannot grow without limit,
# explicitly cleared at task boundaries via `clear_magika_cache`.
_CACHE_LOCK = threading.Lock()
_MAGIKA_CACHE = TTLCache(maxsize=4096, ttl=3600)


def _get_magika():
    """Build (once) and return the process-wide Magika instance, or None."""
    global _MAGIKA_INSTANCE
    if not HAVE_MAGIKA:
        return None
    if _MAGIKA_INSTANCE is not None:
        return _MAGIKA_INSTANCE
    with _MODEL_LOCK:
        if _MAGIKA_INSTANCE is not None:
            return _MAGIKA_INSTANCE
        kwargs = {}
        if MAGIKA_MODEL_DIR:
            model_dir = Path(MAGIKA_MODEL_DIR)
            if model_dir.is_dir():
                kwargs["model_dir"] = model_dir
            else:
                log.warning("magika model_dir '%s' does not exist, falling back to the bundled model", MAGIKA_MODEL_DIR)
        prediction_mode = getattr(_magika_module, "PredictionMode", None)
        if prediction_mode is not None:
            try:
                kwargs["prediction_mode"] = prediction_mode(MAGIKA_PREDICTION_MODE)
            except ValueError:
                log.warning(
                    "invalid magika prediction_mode '%s', using the library default (high_confidence)", MAGIKA_PREDICTION_MODE
                )
        try:
            _MAGIKA_INSTANCE = _magika_module.Magika(**kwargs)
            log.debug("magika initialised: module %s, model %s", _module_version(), _model_name())
        except Exception as e:
            log.error("failed to initialise magika: %s", e)
            _MAGIKA_INSTANCE = None
    return _MAGIKA_INSTANCE


def _module_version() -> str:
    with contextlib.suppress(Exception):
        return _MAGIKA_INSTANCE.get_module_version()
    return ""


def _model_name() -> str:
    with contextlib.suppress(Exception):
        return _MAGIKA_INSTANCE.get_model_name()
    return ""


def _result_to_dict(result) -> dict:
    """Normalise a MagikaResult across the 0.5.x / 0.6.x / 1.x APIs."""
    # 0.6+ exposes .ok/.status; 0.5.x exposes .output directly.
    if hasattr(result, "ok") and not result.ok:
        log.debug("magika returned a non-ok status: %s", getattr(result, "status", "unknown"))
        return {}

    output = getattr(result, "output", None)
    if output is None:
        return {}

    # 0.6+: output.label (ContentTypeLabel str-enum). 0.5.x: output.ct_label.
    label = getattr(output, "label", None) or getattr(output, "ct_label", None)
    if label is None:
        return {}

    score = getattr(result, "score", None)
    if score is None:
        # 0.5.x kept the score on the dl/output sub-object.
        score = getattr(output, "score", None) or getattr(getattr(result, "dl", None), "score", None)

    info = {
        "label": str(label),
        "description": getattr(output, "description", "") or "",
        "mime_type": getattr(output, "mime_type", "") or "",
        "group": getattr(output, "group", "") or "",
        "is_text": bool(getattr(output, "is_text", False)),
        "extensions": list(getattr(output, "extensions", []) or []),
        "score": round(float(score), 4) if score is not None else None,
        "model": _model_name(),
        "version": _module_version(),
    }

    # Why the model's raw guess was overridden (low confidence, extension
    # override, ...). Useful when triaging a surprising label.
    overwrite_reason = getattr(getattr(result, "prediction", None), "overwrite_reason", None)
    if overwrite_reason is not None and str(overwrite_reason) != "none":
        info["overwrite_reason"] = str(overwrite_reason)
        dl_label = getattr(getattr(getattr(result, "prediction", None), "dl", None), "label", None)
        if dl_label is not None and str(dl_label) != info["label"]:
            info["dl_label"] = str(dl_label)

    info["low_confidence"] = info["score"] is not None and info["score"] < MAGIKA_MIN_SCORE
    return info


def magika_info(file_path: str) -> dict:
    """Identify `file_path` with Magika.

    Returns {} when magika is disabled, unavailable, or the file could not
    be identified -- callers key off the empty dict to omit the field
    entirely rather than storing a blank one. Results below `min_score` are
    still returned (they are evidence) but carry `low_confidence: True` so
    the UI can render them as weak.
    """
    if not MAGIKA_ENABLED or not HAVE_MAGIKA or not file_path:
        return {}

    with _CACHE_LOCK:
        cached = _MAGIKA_CACHE.get(file_path)
        if cached is not None:
            return dict(cached)

    info = {}
    try:
        if not os.path.isfile(file_path):
            return {}
        size = os.path.getsize(file_path)
        if size <= 0:
            return {}
        if MAGIKA_MAX_FILE_SIZE and size > MAGIKA_MAX_FILE_SIZE * 1024 * 1024:
            log.debug("magika: skipping %s, %d MB exceeds max_file_size", file_path, size // (1024 * 1024))
            return {}
        magika = _get_magika()
        if magika is None:
            return {}
        info = _result_to_dict(magika.identify_path(Path(file_path)))
    except OSError as e:
        log.debug("magika: unable to read %s: %s", file_path, e)
        return {}
    except Exception as e:
        # Never let content identification take down processing.
        log.warning("magika failed on %s: %s", file_path, e)
        return {}

    with _CACHE_LOCK:
        _MAGIKA_CACHE[file_path] = info
    return dict(info)


def clear_magika_cache():
    """Drop the per-task result cache. Call at task boundaries."""
    with _CACHE_LOCK:
        _MAGIKA_CACHE.clear()
