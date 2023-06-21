from base64 import urlsafe_b64decode
from xml.etree import ElementTree as ET
from lib.cuckoo.common.config import Config

from django.shortcuts import render


web_cfg = Config("web")
cape_cfg = Config()

if cape_cfg.cuckoo.machinery == "kvm":
    try:
        import libvirt
    except ImportError:
        print("Missed python-libvirt. Use extra/poetry_libvirt_installer.sh")


def index(request, task_id, session_data):
    """ESXi support added by @CarsonHrusovsky -> https://github.com/kevoreilly/CAPEv2/issues/1613"""
    vncport = None
    if cape_cfg.cuckoo.machinery == "kvm":
        dsn = "qemu:///system"
        conn = libvirt.open(dsn)
        recording_name = ""
    elif cape_cfg.cuckoo.machinery == "esxi":
        machines_and_ports = web_cfg.guacamole.labels_and_ports
        machine_list = machines_and_ports.split()
        machine_pairings = []
        machine_pairings = [item.split(":") for item in machine_list]
        labelSize = len(machine_pairings)
    else:
        return render(
            request,
            "guac/error.html",
            {"error_msg": "Not supported machinery, you need to implement support for your machinery", "error": "remote session", "task_id": task_id},
        )
    session_id, label, guest_ip = urlsafe_b64decode(session_data).decode("utf8").split("|")
    recording_name = f"{task_id}_{session_id}"


    try:
        if cape_cfg.cuckoo.machinery == "kvm":
            if conn:
                dom = conn.lookupByName(label)
                if dom:
                    state = dom.state(flags=0)
                    if state:
                        if state[0] == 1:
                            vmXml = dom.XMLDesc(0)
                            root = ET.fromstring(vmXml)
                            graphics = root.find('./devices/graphics[@type="vnc"]')
                            vncport = graphics.get("port") if graphics else None
                    else:
                        return render(request, "guac/wait.html", {"task_id": task_id})

        elif cape_cfg.cuckoo.machinery == "esxi":
            for x in range(labelSize):
                if label == machine_pairings[x][0]:
                    vncport = int(machine_pairings[x][1])
            if not vncport:
                return render(
                request,
                "guac/error.html",
                {"error_msg": "Machine Label not found. Check configuration within /opt/CAPEv2/custom/conf/web.conf and ensure the name is provided there correctly. Expected format is VirtualMachineName:VNCPortNumber.", "error": "remote session", "task_id": task_id},
            )
    except Exception as e:
        return render(
            request,
            "guac/error.html",
            {"error_msg": str(e), "error": "remote session", "task_id": task_id},
        )

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
