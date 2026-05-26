import functools
import signal
import subprocess
from typing import Union

def pass_signal(proc, signum, frame):
    proc.send_signal(signum)


def run_tool(*args, **kwargs) -> Union[bytes, str]:
    """Start a subprocess to run the given tool. Make sure to pass a SIGTERM signal to
    that process if it is received.
    """
    kwargs["stdout"] = subprocess.PIPE
    old_handler = None
    try:
        proc = subprocess.Popen(*args, **kwargs)
        old_handler = signal.signal(signal.SIGTERM, functools.partial(pass_signal, proc))
        (stdout, stderr) = proc.communicate()
        return stdout
    finally:
        if old_handler:
            signal.signal(signal.SIGTERM, old_handler)
