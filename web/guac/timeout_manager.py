"""
Timeout management for Guacamole interactive analysis sessions.
Tracks idle time and signals the CAPE analyzer to finish when the session
has been idle for longer than the configured threshold.
"""
import asyncio
import hashlib
import ipaddress
import logging
import ntpath
import posixpath
import time
from typing import Optional

from lib.cuckoo.common.config import Config

try:
    import aiohttp

    HAS_AIOHTTP = True
except ImportError:
    aiohttp = None
    HAS_AIOHTTP = False

logger = logging.getLogger("guac-session")
web_cfg = Config("web")
REQUEST_TIMEOUT_SECONDS = 10


async def _agent_get_json(vm_ip: str, path: str) -> dict:
    """GET JSON from the guest agent at *vm_ip*."""
    url = f"http://{vm_ip}:8000{path}"
    if HAS_AIOHTTP:
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                resp.raise_for_status()
                return await resp.json(content_type=None)
    else:
        import json
        import urllib.request

        def _sync():
            with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read().decode("utf-8"))

        return await asyncio.to_thread(_sync)


async def _agent_post_form(vm_ip: str, path: str, data: dict) -> int:
    """POST form data to the guest agent and return the HTTP status code."""
    url = f"http://{vm_ip}:8000{path}"
    if HAS_AIOHTTP:
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, data=data) as resp:
                return resp.status
    else:
        import urllib.parse
        import urllib.request

        def _sync():
            encoded = urllib.parse.urlencode(data).encode("utf-8")
            req = urllib.request.Request(url, data=encoded, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                return resp.getcode()

        return await asyncio.to_thread(_sync)


class SessionTimeoutManager:
    """Tracks idle time for a Guacamole session and signals analysis completion."""

    def __init__(
        self,
        vm_ip: str,
        user: str,
        session_id: str = "unknown",
        task_id: Optional[str] = None,
    ):
        self.vm_ip = vm_ip or "unknown"
        self.user = user or "unknown_user"
        self.session_id = session_id or "unknown_session"
        self.task_id = str(task_id) if task_id else None
        self.last_activity = self._now_ms()
        self.is_active = True

        try:
            self.idle_timeout_seconds = max(int(getattr(web_cfg.guacamole, "idle_timeout_seconds", 0)), 0)
            if self.idle_timeout_seconds > 0:
                self.activity_check_interval = max(int(getattr(web_cfg.guacamole, "activity_check_interval", 30)), 1)
            else:
                self.activity_check_interval = None
        except (AttributeError, TypeError, ValueError):
            self.idle_timeout_seconds = 0
            self.activity_check_interval = None

        if self.idle_timeout_seconds > 0:
            logger.info(
                "Timeout manager created: %s@%s (task=%s, %sms timeout)",
                self.user,
                self.vm_ip,
                self.task_id,
                self.idle_timeout_seconds,
            )
        else:
            logger.info("Timeout manager created with idle timeout disabled for %s@%s", self.user, self.vm_ip)

    @staticmethod
    def _now_ms() -> int:
        return int(time.monotonic() * 1000)

    def update_activity(self) -> None:
        self.last_activity = self._now_ms()

    def get_idle_time_ms(self) -> int:
        return self._now_ms() - self.last_activity

    def is_timed_out(self) -> bool:
        return self.idle_timeout_seconds > 0 and self.get_idle_time_ms() > (self.idle_timeout_seconds * 1000)

    def set_inactive(self) -> None:
        self.is_active = False

    async def complete_analysis(self) -> bool:
        """Create the signal folder on the guest to end the analysis.
        This is the same mechanism used by the "End Session" button in the web UI
        (see ``web/apiv2/views.py :: tasks_status``).  Returns True on success.
        """
        if not self.vm_ip or self.vm_ip == "unknown":
            logger.error("No valid VM IP for session %s — cannot signal completion", self.session_id)
            return False
        try:
            ipaddress.ip_address(self.vm_ip)
        except ValueError:
            logger.error("Invalid VM IP address %r for session %s — cannot signal completion", self.vm_ip, self.session_id)
            return False
        if not self.task_id:
            logger.error("No task ID for session %s — cannot signal completion", self.session_id)
            return False
        try:
            guest_env, guest_system = await asyncio.gather(
                _agent_get_json(self.vm_ip, "/environ"),
                _agent_get_json(self.vm_ip, "/system"),
            )
            completion_folder = hashlib.md5(f"cape-{self.task_id}".encode()).hexdigest()
            dest = self._build_folder_path(guest_env, guest_system, completion_folder)
            logger.info(
                "Creating completion folder for task %s on %s: %s",
                self.task_id,
                self.vm_ip,
                dest,
            )
            status_code = await _agent_post_form(self.vm_ip, "/mkdir", {"dirpath": dest})
            if status_code == 200:
                logger.info("Completion folder created for task %s on %s (HTTP %s)", self.task_id, self.vm_ip, status_code)
                return True
            logger.warning(
                "Completion folder request returned HTTP %s for task %s on %s",
                status_code,
                self.task_id,
                self.vm_ip,
            )
            return False
        except Exception as exc:
            logger.error("Failed to signal completion for task %s on %s: %s", self.task_id, self.vm_ip, exc)
            return False

    @staticmethod
    def _build_folder_path(guest_env: dict, guest_system: dict, folder_name: str) -> str:
        environ = guest_env.get("environ", {})
        system_name = str(guest_system.get("system", "")).lower()

        if system_name == "windows":
            temp = environ.get("TMP", "C:\\Temp")
            return ntpath.join(temp, folder_name)

        temp = environ.get("TMP", "/tmp")
        return posixpath.join(temp, folder_name)
