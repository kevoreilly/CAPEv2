import subprocess
import sys
from threading import Event, Lock, Thread
from unittest.mock import Mock

from lib.common import abstracts


def test_multiple_processes_drain_their_own_trace_streams(monkeypatch):
    processes = []
    readers = []
    received = bytearray()
    first_reader = Event()
    second_reader = Event()
    lock = Lock()
    iterations = 0
    popen = subprocess.Popen

    class ObservedStream:
        def __init__(self, stream):
            self.stream = stream

        def __iter__(self):
            nonlocal iterations
            with lock:
                iterations += 1
                (first_reader if iterations == 1 else second_reader).set()
            return iter(self.stream)

        def close(self):
            self.stream.close()

    class ScheduledReader(Thread):
        def start(self):
            readers.append(self)
            super().start()
            if len(readers) == 2:
                # Select the second pipe before the launching thread proceeds.
                assert second_reader.wait(5)

    def launch_child(command, **kwargs):
        if not processes:
            script = "import sys; sys.stderr.write('first\\n'); sys.stderr.flush(); sys.stdin.read(1)"
        else:
            # More than a pipe buffer: the child needs its own active reader.
            script = "import sys; sys.stderr.write('second\\n' + 'x' * 262144 + '\\n')"
        process = popen([sys.executable, "-c", script], stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stderr = ObservedStream(process.stderr)
        processes.append(process)
        return process

    monkeypatch.setattr(abstracts, "NetlogFile", Mock)
    monkeypatch.setattr(abstracts, "Thread", ScheduledReader)
    monkeypatch.setattr(abstracts.subprocess, "Popen", launch_child)
    monkeypatch.setattr(abstracts, "append_buffer_to_host", lambda data, connection: received.extend(data))
    package = abstracts.Package(options={})
    try:
        package.execute("first")
        assert first_reader.wait(5)
        package.execute("second")
        processes[0].stdin.close()
        for process in processes:
            assert process.wait(timeout=5) == 0
        for reader in readers:
            reader.join(timeout=5)
            assert not reader.is_alive()
        assert b"first\n" in received
        assert b"second\n" in received
        assert received.count(b"x") == 262144
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            if not process.stdin.closed:
                process.stdin.close()
        for reader in readers:
            reader.join(timeout=5)
        for process in processes:
            process.stderr.close()
        package.finish()
