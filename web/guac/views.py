from base64 import urlsafe_b64decode
from uuid import NAMESPACE_DNS, uuid3
from xml.etree import ElementTree as ET

import libvirt
from django.shortcuts import render


def index(request, task_id, session_data):
    dsn = "qemu:///system"
    conn = libvirt.open(dsn)
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
            status = "RUNNING"
            vmXml = dom.XMLDesc(0)
            root = ET.fromstring(vmXml)
            graphics = root.find("./devices/graphics")
            vncport = graphics.get("port")
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


def playback(request, task_id):
    session_id = uuid3(NAMESPACE_DNS, task_id).hex[:16]
    playback_url = f"{task_id}_{session_id}"

    if playback_url:
        return render(
            request,
            "guac/playback.html",
            {
                "playback_url": playback_url,
            },
        )
    else:
        return render(
            request,
            "guac/error.html",
            {"error_msg": f"File does not exist: {playback_url}", "error": "playback"},
        )
