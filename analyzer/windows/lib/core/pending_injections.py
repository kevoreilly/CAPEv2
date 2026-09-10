# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


def _reserve_pending_injection(pending, identities, pid, identity, is_monitored):
    if is_monitored():
        return False

    if pid not in pending:
        pending.append(pid)
        identities[pid] = identity
        return True

    previous_identity = identities.get(pid)
    if previous_identity is None or identity is None or previous_identity == identity:
        return False

    identities[pid] = identity
    return True


def reserve_pending_injection(pending, identities, lock, pid, identity, is_monitored):
    """Atomically reserve one Windows process instance for monitor injection.

    A PID alone is not a stable process identity because Windows can reuse it.
    Creation time distinguishes a later process from an earlier failed attempt.
    If either identity is unavailable, preserving the reservation is safer than
    injecting the same live process twice.
    """
    with lock:
        return _reserve_pending_injection(pending, identities, pid, identity, is_monitored)


def reserve_pending_process(pending, identities, processes, lock, pid, open_instance, is_monitored):
    """Reserve a process while retaining the handle that identifies it.

    Keeping the handle open prevents Windows from deleting the process object
    and reusing its PID between the identity check and the caller's injection.
    """
    process, identity = open_instance()
    if process is None:
        return None

    previous_process = None
    with lock:
        if identity is not None and _reserve_pending_injection(
            pending,
            identities,
            pid,
            identity,
            is_monitored,
        ):
            previous_process = processes.get(pid)
            processes[pid] = process
            reserved = True
        else:
            reserved = False

    if previous_process is not None and previous_process is not process:
        previous_process.close()
    if reserved:
        return process

    process.close()
    return None


def release_pending_process(pending, identities, processes, lock, pid, expected_process=None):
    """Release one reservation, optionally only when its retained handle matches."""
    with lock:
        process = processes.get(pid)
        if expected_process is not None and process is not expected_process:
            return False

        if pid in pending:
            pending.remove(pid)
        identities.pop(pid, None)
        process = processes.pop(pid, None)

    if process is not None:
        process.close()
    return True
