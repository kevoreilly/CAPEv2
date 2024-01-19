from base64 import urlsafe_b64decode
from xml.etree import ElementTree as ET

from django.shortcuts import render

from lib.cuckoo.common.config import Config

try:
    import libvirt
except ImportError:
    print("Missed python-libvirt. Use extra/libvirt_installer.sh")

machinery = Config().cuckoo.machinery
machinery_dsn = getattr(Config(machinery), machinery).get("dsn", "qemu:///system")


def index(request, task_id, session_data):
    conn = libvirt.open(machinery_dsn)
    recording_name = ""
    if conn:
        try:
            session_id, label, guest_ip = urlsafe_b64decode(session_data).decode("utf8").split("|")
            recording_name = f"{task_id}_{session_id}"
            dom = conn.lookupByName(label)
            if dom:
                state = dom.state(flags=0)
        except Exception as e:
            return render(
                request,
                "guac/error.html",
                {"error_msg": f"{e}", "error": "remote session", "task_id": task_id},
            )

    if state:
        if state[0] == 1:
            vmXml = dom.XMLDesc(0)
            root = ET.fromstring(vmXml)
            graphics = root.find('./devices/graphics[@type="vnc"]')
            vncport = graphics.get("port") if graphics else None
            return render(
                request,
                "guac/index.html",
                {
                    "vncport": vncport,
                    "session_id": session_id,
                    "task_id": task_id,
                    "recording_name": recording_name,
                    "guest_ip": guest_ip,
                },
            )
        else:
            return render(request, "guac/wait.html", {"task_id": task_id})
