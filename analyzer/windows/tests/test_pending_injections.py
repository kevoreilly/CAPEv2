from threading import Lock, Thread

from lib.core.pending_injections import release_pending_process, reserve_pending_injection, reserve_pending_process


class FakeProcess:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_concurrent_reservations_allow_only_one_injection():
    pending = []
    identities = {}
    lock = Lock()
    decisions = []

    def reserve():
        decisions.append(
            reserve_pending_injection(
                pending,
                identities,
                lock,
                pid=4242,
                identity=100,
                is_monitored=lambda: False,
            )
        )

    threads = [Thread(target=reserve), Thread(target=reserve)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(decisions) == [False, True]
    assert pending == [4242]
    assert identities == {4242: 100}


def test_reused_pid_with_new_creation_identity_can_be_reserved():
    pending = [4242]
    identities = {4242: 100}

    reserved = reserve_pending_injection(
        pending,
        identities,
        Lock(),
        pid=4242,
        identity=200,
        is_monitored=lambda: False,
    )

    assert reserved is True
    assert pending == [4242]
    assert identities == {4242: 200}


def test_unknown_or_matching_identity_remains_pending():
    for previous, current in ((100, 100), (None, 200), (100, None)):
        pending = [4242]
        identities = {4242: previous}

        reserved = reserve_pending_injection(
            pending,
            identities,
            Lock(),
            pid=4242,
            identity=current,
            is_monitored=lambda: False,
        )

        assert reserved is False
        assert pending == [4242]
        assert identities == {4242: previous}


def test_monitored_process_is_not_reserved():
    pending = []
    identities = {}

    reserved = reserve_pending_injection(
        pending,
        identities,
        Lock(),
        pid=4242,
        identity=100,
        is_monitored=lambda: True,
    )

    assert reserved is False
    assert pending == []
    assert identities == {}


def test_reserved_process_handle_stays_open_until_caller_finishes():
    process = FakeProcess()
    processes = {}

    reserved = reserve_pending_process(
        [],
        {},
        processes,
        Lock(),
        pid=4242,
        open_instance=lambda: (process, 100),
        is_monitored=lambda: False,
    )

    assert reserved is process
    assert process.closed is False
    assert processes == {4242: process}


def test_rejected_process_handle_is_closed():
    process = FakeProcess()

    reserved = reserve_pending_process(
        [4242],
        {4242: 100},
        {},
        Lock(),
        pid=4242,
        open_instance=lambda: (process, 100),
        is_monitored=lambda: False,
    )

    assert reserved is None
    assert process.closed is True


def test_unidentified_process_is_closed_and_not_reserved():
    process = FakeProcess()
    pending = []

    reserved = reserve_pending_process(
        pending,
        {},
        {},
        Lock(),
        pid=4242,
        open_instance=lambda: (process, None),
        is_monitored=lambda: False,
    )

    assert reserved is None
    assert process.closed is True
    assert pending == []


def test_release_removes_reservation_and_closes_retained_process():
    process = FakeProcess()
    pending = [4242]
    identities = {4242: 100}
    processes = {4242: process}

    released = release_pending_process(pending, identities, processes, Lock(), 4242, process)

    assert released is True
    assert pending == []
    assert identities == {}
    assert processes == {}
    assert process.closed is True


def test_stale_release_cannot_clear_a_newer_process_reservation():
    stale_process = FakeProcess()
    current_process = FakeProcess()
    pending = [4242]
    identities = {4242: 200}
    processes = {4242: current_process}

    released = release_pending_process(pending, identities, processes, Lock(), 4242, stale_process)

    assert released is False
    assert pending == [4242]
    assert identities == {4242: 200}
    assert processes == {4242: current_process}
    assert stale_process.closed is False
    assert current_process.closed is False
