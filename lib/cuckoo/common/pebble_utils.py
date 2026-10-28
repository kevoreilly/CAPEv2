"""Shared helpers for pebble ``ProcessPool`` health checks and bounded teardown.

Used by ``PebbleEngine`` (processing supervisor) and the nested file extractor
pool in ``file_extra_info``.
"""

import logging
import threading

try:
    from pebble.pool.base_pool import PoolStatus
except ImportError:  # pragma: no cover - pebble without PoolStatus
    PoolStatus = None

log = logging.getLogger(__name__)

_POOL_LOOPS = ("_task_scheduler_loop", "_pool_manager_loop", "_message_manager_loop")
_CREATED = PoolStatus.CREATED if PoolStatus is not None else 0
_UNHEALTHY = (PoolStatus.STOPPED, PoolStatus.ERROR) if PoolStatus is not None else (3, 4)


def is_pool_healthy(pool) -> bool:
    """Return True if the pool's management threads are alive and its status is usable.

    ``pool.active`` is a property that calls ``_update_pool_status()``; any
    exception it raises is treated as unhealthy (``hasattr`` only swallows
    ``AttributeError``).
    """
    if pool is None:
        return False
    for attr in _POOL_LOOPS:
        loop = getattr(pool, attr, None)
        if loop is not None and not loop.is_alive():
            return False

    status = getattr(getattr(pool, "_context", None), "status", None)
    if status in _UNHEALTHY:
        return False
    if status != _CREATED:
        try:
            if hasattr(pool, "active") and not pool.active:
                return False
        except Exception:
            return False
    return True


def _join_in_thread(pool, join_timeout):
    """Start ``pool.join(timeout=join_timeout)`` in a daemon thread.

    Returns ``(thread, errors)``; ``errors`` receives any exception raised by
    ``join`` once the thread finishes.
    """
    errors = []

    def _target():
        try:
            pool.join(timeout=join_timeout)
        except BaseException as err:  # noqa: BLE001 - surfaced via errors list
            errors.append(err)

    thread = threading.Thread(target=_target, name="pebble-pool-join", daemon=True)
    thread.start()
    return thread, errors


def teardown_pool(pool, join_timeout, stop_join_timeout, force=False, name="pool") -> bool:
    """Close (or stop) and join ``pool`` within a hard wall-clock bound.

    pebble's ``join(timeout)`` only bounds the queue-drain phase of a CLOSED
    pool. Once the pool is STOPPED, ``join`` calls ``_stop_pool()``, which
    joins the manager threads and SIGKILLs + ``process.join()``s every worker
    with no timeout, so a worker stuck in uninterruptible (D-state) IO blocks
    the caller forever. Every ``join`` here therefore runs in a daemon thread
    that the caller abandons after the bound.

    Returns True if the pool was fully joined, False if it was abandoned.
    Never raises.
    """
    if pool is None:
        return True
    try:
        graceful = not force and is_pool_healthy(pool)
        if graceful:
            pool.close()
            thread, errors = _join_in_thread(pool, join_timeout)
            # Allow the post-drain stop+reap that join() performs internally.
            thread.join(join_timeout + stop_join_timeout)
            if not thread.is_alive() and not errors:
                return True
            log.warning(
                "%s did not drain within %ss (%s); force-stopping",
                name,
                join_timeout,
                errors[0] if errors else "join still running",
            )
        else:
            thread = None

        try:
            pool.stop()
        except Exception as stop_err:
            log.debug("%s: pool.stop() raised: %s", name, stop_err)

        if thread is not None and thread.is_alive():
            # The graceful join() observes the STOPPED status and runs the
            # reap itself; starting a second join() would race _stop_pool().
            thread.join(stop_join_timeout)
            reaped = not thread.is_alive()
        else:
            thread, errors = _join_in_thread(pool, stop_join_timeout)
            thread.join(stop_join_timeout)
            reaped = not thread.is_alive() and not errors
        if not reaped:
            log.error("%s did not reap within %ss after force-stop; abandoning", name, stop_join_timeout)
        return reaped
    except Exception:
        log.debug("%s: teardown raised", name, exc_info=True)
        return False
