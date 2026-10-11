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
# Set once the dispatcher failed to load, so a broken setup is not retried on every single tool run
_DOCKER_DISPATCHER_FAILED = False


def pass_signal(proc, signum, frame):
    proc.send_signal(signum)


def _is_docker_extra_info_enabled() -> bool:
    try:
        integration_conf = Config("integrations")
        docker_conf = getattr(integration_conf, "docker_extra_info", None)
        if docker_conf and docker_conf.get("enabled", False):
            return True
    except Exception:
        pass
    try:
        processing_conf = Config("processing")
        proc_docker_conf = getattr(processing_conf, "docker_extra_info", None)
        if proc_docker_conf and proc_docker_conf.get("enabled", False):
            return True
    except Exception:
        pass
    return False


def run_tool(*args, **kwargs) -> Union[bytes, str]:
    """Start a subprocess to run the given tool, or execute it inside its designated
    Docker container if Docker integration is enabled and configured for this tool.
    Make sure to pass a SIGTERM signal to that process if it is received.
    """
    global _DOCKER_DISPATCHER, _DOCKER_DISPATCHER_FAILED

    docker_enabled = _is_docker_extra_info_enabled()

    if docker_enabled and not _DOCKER_DISPATCHER_FAILED:
        # Lazily load dispatcher to avoid circular dependency loops
        if _DOCKER_DISPATCHER is None:
            try:
                from lib.cuckoo.common.integrations.file_extra_info import ToolDispatcher

                _DOCKER_DISPATCHER = ToolDispatcher()
            except Exception as e:
                _DOCKER_DISPATCHER_FAILED = True
                log.error("Failed to load ToolDispatcher, running tools on the host: %s", str(e))

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
    if kwargs.get("universal_newlines") or kwargs.get("text") or kwargs.get("encoding"):
        kwargs.setdefault("errors", "replace")
    old_handler = None
    try:
        proc = subprocess.Popen(*args, **kwargs)
        try:
            old_handler = signal.signal(signal.SIGTERM, functools.partial(pass_signal, proc))
        except ValueError:
            old_handler = None
        (stdout, stderr) = proc.communicate()
        return stdout
    finally:
        if old_handler:
            signal.signal(signal.SIGTERM, old_handler)
