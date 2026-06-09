import uuid
from base64 import urlsafe_b64decode

import json
import logging
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render, redirect

from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database

logger = logging.getLogger("guac-session")


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


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def direct_vnc_host_port(request, host, port):
    token = uuid.uuid4()
    try:
        guac_session = db.create_guac_session(
            token=token,
            task_id=0,
            vm_label=str(port),
            guest_ip=host,
        )
    except Exception as e:
        return _error(request, 0, f"Failed to create Guacamole session: {e}")

    clean_host = "".join(c for c in host if c.isalnum() or c in ".-_")
    recording_name = f"direct_{clean_host}_{port}_{str(token)[:8]}"

    response = render(request, "guac/index.html", {
        "session_id": str(token),
        "task_id": 0,
        "recording_name": recording_name,
        "vnc_host": host,
        "vnc_port": port,
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


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def direct_vnc_vm(request, vm_name):
    override = request.GET.get("override") == "true"
    if not override:
        from lib.cuckoo.core.data.guac_session import GuacSession
        session = db.session()
        active_session = session.query(GuacSession).filter_by(vm_label=vm_name).first()
        if active_session:
            return render(request, "guac/warn.html", {"vm_name": vm_name})

    if not LIBVIRT_AVAILABLE:
        return _error(request, 0, "Libvirt not available")

    if machinery not in machinery_available:
        return _error(request, 0, f"Machinery type '{machinery}' is not supported")

    is_running = False
    vm_exists = False
    error_msg = ""

    conn = None
    try:
        conn = libvirt.open(machinery_dsn)
        if conn:
            try:
                dom = conn.lookupByName(vm_name)
                if dom:
                    vm_exists = True
                    state = dom.state(flags=0)
                    is_running = state and state[0] == 1
            except Exception as e:
                error_msg = str(e)
    except Exception as e:
        error_msg = str(e)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    if error_msg and not vm_exists:
        return _error(request, 0, error_msg)

    if not vm_exists:
        return _error(request, 0, f"VM {vm_name} not found")

    if not is_running:
        return render(request, "guac/start.html", {"vm_name": vm_name})

    token = uuid.uuid4()
    try:
        guac_session = db.create_guac_session(
            token=token,
            task_id=0,
            vm_label=vm_name,
            guest_ip="",
        )
    except Exception as e:
        return _error(request, 0, f"Failed to create Guacamole session: {e}")

    recording_name = f"direct_{vm_name}_{str(token)[:8]}"

    # Determine if it was started by the VNC Console
    machine = db.view_machine_by_label(vm_name)
    started_by_console = machine.locked if machine else False

    response = render(request, "guac/index.html", {
        "session_id": str(token),
        "task_id": 0,
        "recording_name": recording_name,
        "vnc_host": vm_name,
        "vnc_port": "auto",
        "started_by_console": started_by_console,
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


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def direct_vnc_vm_start(request, vm_name):
    if not LIBVIRT_AVAILABLE:
        return _error(request, 0, "Libvirt not available")

    if machinery not in machinery_available:
        return _error(request, 0, f"Machinery type '{machinery}' is not supported")

    if request.method != "POST":
        return _error(request, 0, "Invalid request method")

    start_mode = request.POST.get("start_mode", "snapshot")

    conn = None
    try:
        conn = libvirt.open(machinery_dsn)
        if not conn:
            return _error(request, 0, "Could not connect to hypervisor")

        try:
            dom = conn.lookupByName(vm_name)
        except Exception as e:
            return _error(request, 0, f"VM {vm_name} not found: {e}")

        # Check if already running
        state = dom.state(flags=0)
        is_running = state and state[0] == 1
        if is_running:
            return redirect("direct_vnc_vm", vm_name=vm_name)

        # Lock the machine in DB
        machine = db.view_machine_by_label(vm_name)
        if machine:
            db.lock_machine(machine)
            db.session.commit()

        if start_mode == "snapshot":
            snapshot_name = machine.snapshot if (machine and machine.snapshot) else None
            if not snapshot_name:
                try:
                    snapshot_names = dom.snapshotListNames(flags=0)
                    if snapshot_names:
                        snapshot_name = snapshot_names[0]
                except Exception:
                    pass

            if not snapshot_name:
                if machine:
                    db.unlock_machine(machine)
                    db.session.commit()
                return _error(request, 0, f"No snapshot configured or found for VM {vm_name}")

            try:
                snap = dom.snapshotLookupByName(snapshot_name, flags=0)
                dom.revertToSnapshot(snap, flags=0)
            except Exception as e:
                if machine:
                    db.unlock_machine(machine)
                    db.session.commit()
                return _error(request, 0, f"Failed to restore snapshot: {e}")
        else:
            # Start dirty
            try:
                dom.create()
            except Exception as e:
                if machine:
                    db.unlock_machine(machine)
                    db.session.commit()
                return _error(request, 0, f"Failed to power on VM dirty: {e}")

        return redirect("direct_vnc_vm", vm_name=vm_name)

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def direct_vnc_vm_shutdown(request, vm_name):
    if not LIBVIRT_AVAILABLE:
        return JsonResponse({"status": "error", "message": "Libvirt not available"}, status=500)

    if machinery not in machinery_available:
        return JsonResponse({"status": "error", "message": f"Machinery type '{machinery}' is not supported"}, status=400)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "Invalid request method"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        data = {}

    force = data.get("force", False)

    conn = None
    try:
        conn = libvirt.open(machinery_dsn)
        if not conn:
            return JsonResponse({"status": "error", "message": "Could not connect to hypervisor"}, status=500)

        try:
            dom = conn.lookupByName(vm_name)
        except Exception as e:
            return JsonResponse({"status": "error", "message": f"VM {vm_name} not found: {e}"}, status=404)

        try:
            if force:
                dom.destroy()
            else:
                dom.shutdown()
        except Exception as e:
            logger.error("Failed to shutdown VM %s: %s", vm_name, e)

        # Unlock the machine in DB
        machine = db.view_machine_by_label(vm_name)
        if machine:
            db.unlock_machine(machine)
            db.session.commit()

        return JsonResponse({"status": "success"})

    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

