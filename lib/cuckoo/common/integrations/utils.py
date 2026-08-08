import functools
import os
import logging
import signal
import subprocess
from typing import Union
from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)

# Global variable to store lazily loaded Docker ToolDispatcher
_DOCKER_DISPATCHER = None


def pass_signal(proc, signum, frame):
    proc.send_signal(signum)


def run_tool(*args, **kwargs) -> Union[bytes, str]:
    """Start a subprocess to run the given tool, or execute it inside its designated
    Docker container if Docker integration is enabled and configured for this tool.
    Make sure to pass a SIGTERM signal to that process if it is received.
    """
    global _DOCKER_DISPATCHER

    try:
        processing_conf = Config("processing")
        docker_enabled = processing_conf.docker_extra_info.get("enabled", False)
    except Exception:
        docker_enabled = False

    if docker_enabled:
        # Lazily load dispatcher to avoid circular dependency loops
        if _DOCKER_DISPATCHER is None:
            try:
                from lib.cuckoo.common.integrations.file_extra_info import ToolDispatcher
                _DOCKER_DISPATCHER = ToolDispatcher()
            except Exception as e:
                log.error("Failed to load ToolDispatcher: %s", str(e))

        if _DOCKER_DISPATCHER:
            cmd_args = args[0] if args else kwargs.get("args")
            if cmd_args and isinstance(cmd_args, list):
                binary_path = cmd_args[0]
                binary_name = os.path.basename(binary_path)

                if _DOCKER_DISPATCHER.is_container_configured(binary_name):
                    log.debug("Routing execution of %s inside its Docker container", binary_name)
                    return _DOCKER_DISPATCHER.execute_in_container(binary_name, cmd_args, **kwargs)

    # Fallback to direct local host execution
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
