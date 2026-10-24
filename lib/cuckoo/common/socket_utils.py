import json
import logging
import socket
import tempfile
import threading
from pathlib import Path

from lib.cuckoo.common.path_utils import path_exists

log = logging.getLogger("socket-aux")
lock = threading.Lock()


def send_socket_command(socket_path: str, command: str, *args, **kwargs):
    """
    Sends a command via a Unix domain socket to a root-executed component.

    Args:
        socket_path (str): The path to the Unix domain socket.
        command (str): The command to send.
        args: Additional positional arguments to include in the command.
        kwargs: Additional keyword arguments to include in the command.

    Returns:
        dict: The response from the socket, parsed from JSON. If there is a timeout or connection error,
            a dictionary with an "exception" key will be returned.

    Logs:
        Critical errors if the socket path does not exist or if unable to connect to the Unix socket.
    """
    """Aux function to send commands via socket to root executed components"""
    if not path_exists(socket_path):
        log.critical("Unable to passthrough root command (%s) as the rooter unix socket: %s doesn't exist", socket_path, command)
        return

    ret = None
    with lock:
        with tempfile.NamedTemporaryFile(mode="w+", delete=True) as unixpath:
            unix_path = Path(unixpath.name)

        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            s.bind(str(unix_path))

            try:
                s.connect(socket_path.encode())
            except socket.error as e:
                log.critical("Unable to passthrough root command as we're unable to connect to the unix socket: %s", e)
                return

            s.send(
                json.dumps(
                    {
                        "command": command,
                        "args": args,
                        "kwargs": kwargs,
                    }
                ).encode()
            )

            try:
                ret = json.loads(s.recv(0x10000))
            except socket.timeout:
                ret = {"exception": f"{socket_path} response timeout", "output": ""}

            return ret
        finally:
            s.close()
            unix_path.unlink(missing_ok=True)


if "__main__" == __name__:
    print(send_socket_command("/tmp/cape-fstab", "add_entry", ["192.168.1.1", "/opt/CAPEv2/workers/192.168.1.1"], {}))
