import uuid
from base64 import urlsafe_b64decode
from xml.etree import ElementTree as ET

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database


class conditional_login_required:
    def __init__(self, decorator, condition):
        self.decorator = decorator
        self.condition = condition

    def __call__(self, func):
        if not self.condition:
            return func
        return self.decorator(func)

try:
    import libvirt
    LIBVIRT_AVAILABLE = True
except ImportError:
    LIBVIRT_AVAILABLE = False

machinery = Config().cuckoo.machinery
machinery_available = ["kvm", "qemu"]
machinery_dsn = getattr(Config(machinery), machinery).get("dsn", "qemu:///system")
db = Database()


def _error(request, task_id, msg):
    return render(request, "guac/error.html", {
        "error_msg": msg, "error": "remote session", "task_id": task_id,
    })


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request, task_id, session_data):
    if not LIBVIRT_AVAILABLE:
        return _error(request, task_id, "Libvirt not available")

    if machinery not in machinery_available:
        return _error(request, task_id, f"Machinery type '{machinery}' is not supported")

    conn = None
    try:
        conn = libvirt.open(machinery_dsn)
        if not conn:
            return _error(request, task_id, "Could not connect to hypervisor")

        try:
            session_id, label, guest_ip = (
                urlsafe_b64decode(session_data).decode("utf8").split("|")
            )
        except Exception as e:
            return _error(request, task_id, str(e))

        try:
            dom = conn.lookupByName(label)
        except Exception as e:
            return _error(request, task_id, str(e))

        if not dom:
            return _error(request, task_id, f"VM {label} not found")

        state = dom.state(flags=0)
        if not state or state[0] != 1:
            return render(request, "guac/wait.html", {"task_id": task_id})

        # VM is running — get or create a session token
        recording_name = f"{task_id}_{session_id}"
        token = uuid.uuid4()

        guac_session = db.create_guac_session(
            token=token,
            task_id=int(task_id),
            vm_label=label,
            guest_ip=guest_ip,
        )

        response = render(request, "guac/index.html", {
            "session_id": session_id,
            "task_id": task_id,
            "recording_name": recording_name,
        })

        response.set_cookie(
            "guac_session",
            str(guac_session.token),
            httponly=True,
            secure=request.is_secure(),
            samesite="Lax",
            path="/guac/",
        )

        return response

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
