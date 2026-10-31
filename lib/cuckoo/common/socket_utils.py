import json
import logging
import socket
import tempfile
import threading
from pathlib import Path

from lib.cuckoo.common.path_utils import path_exists

log = logging.getLogger("socket-aux")
lock = threading.Lock()


DEFAULT_SOCKET_TIMEOUT = 60


def send_socket_command(socket_path: str, command: str, *args, socket_timeout: float | None = DEFAULT_SOCKET_TIMEOUT, **kwargs):
    """
    Sends a command via a Unix domain socket to a root-executed component.

    Args:
        socket_path (str): The path to the Unix domain socket.
        command (str): The command to send.
        args: Additional positional arguments to include in the command.
        socket_timeout (float | None): Seconds to wait for the response. Not forwarded to the server.
            Set explicitly on the socket so the wait is bounded even when no process-wide
            socket.setdefaulttimeout() is configured.
        kwargs: Additional keyword arguments to include in the command.

    Returns:
        dict: The response from the socket, parsed from JSON. If there is a timeout or a send/receive error,
            a dictionary with an "exception" key will be returned.
        None: If the socket path does not exist or the connection fails.

    Logs:
        Critical errors if the socket path does not exist or if unable to connect to the Unix socket.
    """
    if not path_exists(socket_path):
        log.critical("Unable to passthrough root command (%s) as the rooter unix socket: %s doesn't exist", socket_path, command)
        return

    with lock:
        # Bind the reply socket inside a private (0700) directory: no name reuse race as with
        # mktemp()/NamedTemporaryFile, and the path is unique per call, so a late reply to a
        # previous (timed out) call can never be read as the answer to this one.
        reply_dir = Path(tempfile.mkdtemp(prefix="cuckoo-sock-"))
        reply_path = reply_dir / "reply.sock"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            s.settimeout(socket_timeout)
            s.bind(str(reply_path))

            try:
                s.connect(socket_path.encode())
            except OSError as e:
                log.critical("Unable to passthrough root command as we're unable to connect to the unix socket: %s", e)
                return

            try:
                s.send(json.dumps({"command": command, "args": args, "kwargs": kwargs}).encode())
                return json.loads(s.recv(0x10000))
            except socket.timeout:
                return {"exception": f"{socket_path} response timeout", "output": ""}
            except OSError as e:
                return {"exception": f"{socket_path} socket error: {e}", "output": ""}
        finally:
            s.close()
            reply_path.unlink(missing_ok=True)
            reply_dir.rmdir()


if "__main__" == __name__:
    print(send_socket_command("/tmp/cape-fstab", "add_entry", ["192.168.1.1", "/opt/CAPEv2/workers/192.168.1.1"], {}))
