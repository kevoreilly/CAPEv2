import json
import logging
import os
import subprocess
import time
from datetime import datetime
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.exceptions import CuckooPackageError
from lib.common.results import NetlogFile, append_buffer_to_host

# Set up logging
log = logging.getLogger(__name__)

__author__ = "jonisworking,theoleecj2"
__version__ = "1.0.0"

# Constants for Docker configuration
DOCKER_LOG_NAME = "tracee.data"
DOCKER_CONTAINER_NAME = "tracee"  # Name of the Docker container to monitor
TRACEE_VERSION = "latest"


def is_docker_installed() -> bool:
    """
    Check if Docker is installed on the system.
    """
    # Docker must be installed manually on the VM
    # Check if Docker is installed
    completed_process = subprocess.run(["dpkg-query", "-l", "docker"], capture_output=True)
    if b"no packages found" in completed_process.stdout:
        return False
    else:
        return True


def is_docker_container_running(container_name):
    """
    Check if the Docker container is currently running.
    """
    try:
        # Check if the container is running
        completed_process = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name], capture_output=True, text=True
        )
        return completed_process.stdout.strip() == "true"
    except Exception as e:
        log.error(f"Error checking container status: {e}")
        return False


def start_docker_container(container_name, tracee_version):
    """
    Start the Docker container.
    """
    try:
        # Checks
        tracee_cmd = [
            "sudo docker run --name tracee -d --pid=host --cgroupns=host --privileged "
            + f"-v /etc/os-release:/etc/os-release-host:ro -v {os.getcwd()}/tracee-artifacts/:/tmp/tracee/out/host -v /var/run:/var/run:ro -v {os.getcwd()}/modules/auxiliary/tracee:/policy "
            + "aquasec/tracee:latest --output json --output option:parse-arguments,exec-env,exec-hash --policy /policy/policy.yml --cache cache-type=mem --cache mem-cache-size=1024 "
            + "--capture bpf --capture module"
        ][0]

        log.debug(tracee_cmd)

        # Run Docker cmd to start the container
        result = subprocess.run(
            tracee_cmd,
            shell=True,
            capture_output=True,
            text=True,
        )
        log.debug(f"Docker container started: {result.stdout}")

        # Health check to wait until Tracee begins recording events
        health_check_failed = True

        while health_check_failed:
            time.sleep(10)
            result = subprocess.run("strace echo tracee-health-check-1903ae", shell=True, capture_output=True, text=True)
            log.info(result.stdout)
            health_check_log = subprocess.run("docker logs tracee", shell=True, capture_output=True, text=True)
            log.info(health_check_log.stdout)
            if "1903ae" in health_check_log.stdout:
                health_check_failed = False

    except subprocess.CalledProcessError as e:
        log.error(f"Error starting Docker container '{container_name}': {e}")


def stop_docker_container(container_name):
    """
    Stop the Docker container.
    """
    try:
        # Run the Docker command to stop the container
        result = subprocess.run(["sudo", "docker", "stop", container_name], check=True, capture_output=True, text=True)
        log.debug(f"Docker container stopped: {result.stdout}")

    except subprocess.CalledProcessError as e:
        log.error(f"Error stopping Docker container '{container_name}': {e}")


class Docker(Thread, Auxiliary):
    """
    Class for managing Docker operations.
    """

    def __init__(self, options, config):
        """
        Initialize Docker instance.
        """
        log.info("docker start")
        self.enabled = config.tracee_linux
        log.info(self.enabled)
        log.info("Tracee")
        Auxiliary.__init__(self, options, config)
        self.start_time = None
        self.end_time = None

    def thread_send_docker_buffer(self):
        time.sleep(3)
        log.info(self.nc)
        result = subprocess.run("sudo docker ps", shell=True, capture_output=True, text=True)
        log.info(result.stdout)
        result = subprocess.run("sudo docker inspect tracee", shell=True, capture_output=True, text=True)
        container_details = json.loads(result.stdout)[0]
        logpath = container_details["LogPath"]

        cmd = f"sudo tail +1f {logpath}"
        log.info(cmd)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                env={"XAUTHORITY": "/root/.Xauthority", "DISPLAY": ":0"},
            )

            for line in proc.stdout:
                # log.info(line)
                append_buffer_to_host(line, self.nc)
        except Exception as e:
            log.info(e)

    def start(self):
        """
        Start Docker container.
        """
        if not self.enabled:
            return False  # result.stdout

        if not is_docker_installed():
            raise CuckooPackageError("Your VM needs to have Docker installed in order to use Docker functionality (tracee).")

        # Check if the Docker container is already running
        if not is_docker_container_running(DOCKER_CONTAINER_NAME):
            # Start Docker container if it's not running
            log.debug("Starting docker container")
            start_docker_container(DOCKER_CONTAINER_NAME, TRACEE_VERSION)
        else:
            log.debug("Docker container is already running.")

        log.info("Try to stream")

        # stream
        self.nc = NetlogFile()
        self.nc.init("logs/tracee.log", False)
        log.info(self.nc)
        self.thread = Thread(target=self.thread_send_docker_buffer)
        self.thread.start()

        log.info("Streamstart")

        self.start_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    def collect_logs(self):
        """
        Collect Docker container logs.
        """

        log.debug("Tracee module skips log collection as it uses streaming")

    def stop(self) -> bool:
        """
        Stop Docker container.
        """
        log.debug("Tracee module instructed to stop")
        if self.enabled:
            log.debug("Tracee module instructed to stop + was enabled")
            self.end_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            self.collect_logs()

            # Stop the Docker container
            stop_docker_container(DOCKER_CONTAINER_NAME)

            return True
        return False
