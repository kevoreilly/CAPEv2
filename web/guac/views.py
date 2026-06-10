import uuid
import threading
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
web_cfg = Config("web")


def is_vnc_console_enabled():
    enabled = web_cfg.guacamole.get("vnc_console_enabled", False)
    if isinstance(enabled, str):
        return enabled.lower() in ("yes", "true", "on", "1")
    return bool(enabled)


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
    if not is_vnc_console_enabled():
        return _error(request, 0, "VNC Console is disabled in configuration")

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
    if not is_vnc_console_enabled():
        return _error(request, 0, "VNC Console is disabled in configuration")

    if not LIBVIRT_AVAILABLE:
        return _error(request, 0, "Libvirt not available")

    if machinery not in machinery_available:
        return _error(request, 0, f"Machinery type '{machinery}' is not supported")

    is_running = False
    vm_exists = False
    error_msg = ""
    snapshot_names = []
    current_snapshot = None

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
                    if not is_running:
                        try:
                            snapshot_names = dom.snapshotListNames(flags=0)
                        except Exception:
                            pass
                    else:
                        try:
                            if dom.hasCurrentSnapshot() == 1:
                                current_snapshot = dom.currentSnapshot().getName()
                        except Exception:
                            pass

                        if not current_snapshot:
                            current_snapshot = request.session.get(f"snapshot_{vm_name}")
                            if not current_snapshot:
                                machine = db.view_machine_by_label(vm_name) or db.view_machine(vm_name)
                                if machine and machine.snapshot:
                                    current_snapshot = machine.snapshot
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

    # If the VM is running, check for an active Guacamole connection session
    override = request.GET.get("override") == "true"
    if is_running and not override:
        from lib.cuckoo.core.data.guac_session import GuacSession
        session = db.session()
        active_session = session.query(GuacSession).filter_by(vm_label=vm_name).first()
        if active_session:
            return render(request, "guac/warn.html", {"vm_name": vm_name})

    # If the VM is not running, delete any stale GuacSession entries to prevent lockups
    if not is_running:
        try:
            from lib.cuckoo.core.data.guac_session import GuacSession
            session = db.session()
            session.query(GuacSession).filter_by(vm_label=vm_name).delete()
            session.commit()
        except Exception as e:
            logger.error(f"Failed to clear stale GuacSession for VM {vm_name}: {e}")

        is_starting = False
        machine = db.view_machine_by_label(vm_name) or db.view_machine(vm_name)
        if machine:
            if machine.locked_changed_on:
                from datetime import datetime
                # Check if it was locked within the last 90 seconds (startup window)
                delta = datetime.utcnow() - machine.locked_changed_on
                is_starting = delta.total_seconds() < 90

            if is_starting:
                return render(request, "guac/wait.html", {
                    "vm_name": vm_name,
                    "task_id": 0,
                })
            elif machine.locked:
                # Check if this lock belongs to a legitimate active CAPE analysis task
                try:
                    from lib.cuckoo.core.data.guests import Guest
                    from lib.cuckoo.core.data.task import Task
                    from lib.cuckoo.common.constants import TASK_RUNNING
                    
                    session = db.session()
                    active_task = session.query(Task).filter(
                        Task.machine_id == machine.id,
                        Task.status == TASK_RUNNING
                    ).first()
                    
                    active_guest = session.query(Guest).filter(
                        Guest.label == vm_name,
                        Guest.shutdown_on == None
                    ).first()
                except Exception as query_err:
                    logger.error("Failed to query active tasks/guests: %s", query_err)
                    active_task = None
                    active_guest = None

                if active_task or active_guest:
                    # Legitimate task is active, DO NOT unlock! Show wait screen.
                    return render(request, "guac/wait.html", {
                        "vm_name": vm_name,
                        "task_id": active_task.id if active_task else 0,
                    })
                else:
                    # No active task/guest and no active console startup -> stale lock!
                    try:
                        db.unlock_machine(machine)
                        db.session.commit()
                        logger.info("Automatically unlocked stale machine lock for VM '%s'", vm_name)
                    except Exception as db_err:
                        logger.error("Failed to unlock stale machine lock for '%s': %s", vm_name, db_err)

        default_snapshot = machine.snapshot if (machine and machine.snapshot) else None
        return render(request, "guac/start.html", {
            "vm_name": vm_name,
            "snapshots": snapshot_names,
            "default_snapshot": default_snapshot,
        })

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
    machine = db.view_machine_by_label(vm_name) or db.view_machine(vm_name)
    started_by_console = True

    # Determine configured VPNs and Tor/Internet routing options
    from lib.cuckoo.common.config import Config as CapeConfig
    routing = CapeConfig("routing")
    tor_enabled = routing.tor.get("enabled", False)
    internet_interface = routing.routing.get("internet", "none")
    internet_configured = internet_interface and internet_interface != "none"

    vpns_raw = routing.vpn.get("vpns", "")
    vpn_list = []
    if routing.vpn.get("enabled", False) and vpns_raw:
        for vpn_name in [v.strip() for v in vpns_raw.split(",") if v.strip()]:
            vpn_section = getattr(routing, vpn_name, None)
            if vpn_section:
                vpn_list.append({
                    "name": vpn_name,
                    "description": vpn_section.get("description", vpn_name)
                })

    current_route = request.session.get(f"route_{vm_name}", "none")

    response = render(request, "guac/index.html", {
        "session_id": str(token),
        "task_id": 0,
        "recording_name": recording_name,
        "vnc_host": vm_name,
        "vnc_port": "auto",
        "started_by_console": started_by_console,
        "tor_enabled": tor_enabled,
        "internet_configured": internet_configured,
        "vpns": vpn_list,
        "current_route": current_route,
        "current_snapshot": current_snapshot,
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


def bg_revert_and_start(machinery_dsn, vm_name, start_mode, snapshot_name):
    import libvirt
    from lib.cuckoo.core.database import Database
    db = Database()
    conn = None
    try:
        conn = libvirt.open(machinery_dsn)
        if conn:
            dom = conn.lookupByName(vm_name)
            if start_mode == "snapshot":
                snap = dom.snapshotLookupByName(snapshot_name, flags=0)
                dom.revertToSnapshot(snap, flags=0)
            else:
                dom.create()

            # Enforce 'none' (no internet) route by default
            try:
                machine = db.view_machine_by_label(vm_name)
                if machine:
                    from utils.router_manager import route_enable
                    route_enable("none", None, None, machine, None, None)
                    logger.info("Successfully set default 'none' route for VM '%s'", vm_name)
            except Exception as routing_err:
                logger.error(f"Failed to enforce default 'none' route for VM {vm_name}: {routing_err}")

            # Wait for the agent to become available and sync the clock to America/New_York (EST/EDT) zone
            try:
                machine = db.view_machine_by_label(vm_name)
                if machine:
                    import socket
                    import time
                    import requests
                    import pytz
                    import datetime
                    import io

                    ip = machine.ip
                    port = 8000
                    agent_ready = False
                    start_time = time.time()
                    timeout = 180  # 3 minutes timeout

                    logger.info("Waiting for agent to become available on %s:%d to update guest clock...", ip, port)
                    while time.time() - start_time < timeout:
                        # Check if VM is still running
                        try:
                            state = dom.state(flags=0)
                            is_running = state and state[0] == 1
                            if not is_running:
                                logger.info("VM '%s' is no longer running. Aborting guest clock update.", vm_name)
                                break
                        except Exception:
                            pass

                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2.0)
                            result = sock.connect_ex((ip, port))
                            sock.close()
                            if result == 0:
                                session = requests.Session()
                                session.trust_env = False
                                session.proxies = None
                                res = session.get(f"http://{ip}:{port}/", timeout=2.0)
                                if res.status_code == 200:
                                    agent_ready = True
                                    break
                        except Exception:
                            pass
                        time.sleep(2.0)

                    if agent_ready:
                        logger.info("Agent is ready on VM '%s'. Syncing clock...", vm_name)
                        session = requests.Session()
                        session.trust_env = False
                        session.proxies = None

                        # Timezone conversion to EST (America/New_York)
                        try:
                            tz = pytz.timezone("America/New_York")
                            now_est = datetime.datetime.now(tz)
                        except ImportError:
                            now_utc = datetime.datetime.utcnow()
                            if 3 < now_utc.month < 11:
                                offset = datetime.timedelta(hours=-4)
                            else:
                                offset = datetime.timedelta(hours=-5)
                            tz = datetime.timezone(offset)
                            now_est = datetime.datetime.now(tz)

                        date_str = now_est.strftime("%Y-%m-%d %H:%M:%S")
                        platform = (machine.platform or "windows").lower()

                        # Construct guest clock update script
                        if platform == "windows":
                            script_content = f"""import ctypes
import sys

class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", ctypes.c_ushort),
        ("wMonth", ctypes.c_ushort),
        ("wDayOfWeek", ctypes.c_ushort),
        ("wDay", ctypes.c_ushort),
        ("wHour", ctypes.c_ushort),
        ("wMinute", ctypes.c_ushort),
        ("wSecond", ctypes.c_ushort),
        ("wMilliseconds", ctypes.c_ushort),
    ]

st = SYSTEMTIME()
st.wYear = {now_est.year}
st.wMonth = {now_est.month}
st.wDay = {now_est.day}
st.wHour = {now_est.hour}
st.wMinute = {now_est.minute}
st.wSecond = {now_est.second}
st.wMilliseconds = 0

if not ctypes.windll.kernel32.SetLocalTime(ctypes.byref(st)):
    sys.exit(1)
"""
                        else:
                            script_content = f"""import subprocess
import sys

res = subprocess.run(["date", "-s", "{date_str}"])
sys.exit(res.returncode)
"""

                        # Determine temp path on guest
                        temp_path = "C:\\Windows\\Temp" if platform == "windows" else "/tmp"
                        try:
                            env_res = session.get(f"http://{ip}:{port}/environ", timeout=5.0)
                            if env_res.status_code == 200:
                                env_data = env_res.json().get("environ", {})
                                env_upper = {str(k).upper(): v for k, v in env_data.items()}
                                if platform == "windows":
                                    temp_path = env_upper.get("TEMP") or env_upper.get("TMP") or temp_path
                        except Exception as env_err:
                            logger.warning(f"Could not query guest environment on VM '{vm_name}': {env_err}")

                        remote_script_path = f"{temp_path}\\set_clock.py" if platform == "windows" else f"{temp_path}/set_clock.py"

                        files = {
                            "file": ("set_clock.py", io.BytesIO(script_content.encode("utf-8"))),
                        }
                        store_res = session.post(f"http://{ip}:{port}/store", files=files, data={"filepath": remote_script_path}, timeout=10.0)
                        if store_res.status_code == 200:
                            exec_res = session.post(f"http://{ip}:{port}/execpy", data={"filepath": remote_script_path}, timeout=10.0)
                            if exec_res.status_code == 200 and exec_res.json().get("status") == "success":
                                logger.info(f"Successfully updated guest clock for VM '{vm_name}' via /execpy to {date_str} EST")
                            else:
                                logger.error(f"Execpy clock sync failed on VM '{vm_name}': {exec_res.text}")

                            try:
                                session.post(f"http://{ip}:{port}/remove", data={"filepath": remote_script_path}, timeout=5.0)
                            except Exception:
                                pass
                        else:
                            logger.error(f"Store clock sync script failed on VM '{vm_name}': {store_res.text}")
                    else:
                        logger.warning(f"Agent did not become ready within timeout. Skipping clock update for VM '{vm_name}'.")

            except Exception as clock_err:
                logger.error(f"Error during guest clock update for VM '{vm_name}': {clock_err}")

    except Exception as e:
        logger.error(f"Error starting VM {vm_name} in background: {e}")
        try:
            machine = db.view_machine_by_label(vm_name)
            if machine:
                db.unlock_machine(machine)
                db.session.commit()
        except Exception as db_err:
            logger.error(f"Failed to unlock machine {vm_name} after background start error: {db_err}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def direct_vnc_vm_start(request, vm_name):
    if not is_vnc_console_enabled():
        return _error(request, 0, "VNC Console is disabled in configuration")

    if not LIBVIRT_AVAILABLE:
        return _error(request, 0, "Libvirt not available")

    if machinery not in machinery_available:
        return _error(request, 0, f"Machinery type '{machinery}' is not supported")

    if request.method != "POST":
        return _error(request, 0, "Invalid request method")

    start_mode = request.POST.get("start_mode", "snapshot")
    selected_snapshot = request.POST.get("selected_snapshot")

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
            if machine.locked:
                try:
                    from lib.cuckoo.core.data.guests import Guest
                    from lib.cuckoo.core.data.task import Task
                    from lib.cuckoo.common.constants import TASK_RUNNING
                    
                    session = db.session()
                    active_task = session.query(Task).filter(
                        Task.machine_id == machine.id,
                        Task.status == TASK_RUNNING
                    ).first()
                    
                    active_guest = session.query(Guest).filter(
                        Guest.label == vm_name,
                        Guest.shutdown_on == None
                    ).first()
                except Exception:
                    active_task = None
                    active_guest = None

                if active_task or active_guest:
                    return _error(request, active_task.id if active_task else 0, f"VM {vm_name} is currently in use by an active analysis task.")

            db.lock_machine(machine)
            db.session.commit()

        snapshot_name = None
        if start_mode == "snapshot":
            snapshot_name = selected_snapshot or (machine.snapshot if (machine and machine.snapshot) else None)
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

            # Verify snapshot exists before starting thread
            try:
                dom.snapshotLookupByName(snapshot_name, flags=0)
            except Exception as e:
                if machine:
                    db.unlock_machine(machine)
                    db.session.commit()
                return _error(request, 0, f"Failed to restore snapshot: {e}")

        # Initialize route session to 'none' by default
        request.session[f"route_{vm_name}"] = "none"
        request.session[f"snapshot_{vm_name}"] = snapshot_name if start_mode == "snapshot" else None

        # Spawn background thread to start the VM
        threading.Thread(
            target=bg_revert_and_start,
            args=(machinery_dsn, vm_name, start_mode, snapshot_name),
            name=f"start_{vm_name}",
            daemon=True
        ).start()

        return redirect("direct_vnc_vm", vm_name=vm_name)

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def direct_vnc_vm_shutdown(request, vm_name):
    if not is_vnc_console_enabled():
        return JsonResponse({"status": "error", "message": "VNC Console is disabled in configuration"}, status=403)

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

        # Disable active routing if configured
        current_route = request.session.get(f"route_{vm_name}", "none")
        if current_route != "none" and machine:
            try:
                from lib.cuckoo.common.config import Config as CapeConfig
                from utils.router_manager import route_disable
                
                routing = CapeConfig("routing")
                vpns_raw = routing.vpn.get("vpns", "")
                configured_vpns = [v.strip() for v in vpns_raw.split(",") if v.strip()] if vpns_raw else []
                
                interface, rt_table, reject_segments, reject_hostports = get_route_params(
                    current_route, routing, configured_vpns
                )
                route_disable(current_route, interface, rt_table, machine, reject_segments, reject_hostports)
            except Exception as routing_err:
                logger.error(f"Failed to disable routing for {vm_name} on shutdown: {routing_err}")
            finally:
                request.session.pop(f"route_{vm_name}", None)

        # Unlock the machine in DB
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


def get_route_params(route_name, routing, configured_vpns):
    if route_name == "tor":
        return routing.tor.get("interface"), None, None, None
    elif route_name == "internet":
        interface = routing.routing.get("internet", "none")
        rt_table = routing.routing.get("rt_table", "main")
        
        reject_segments = routing.routing.get("reject_segments", "none")
        if reject_segments == "none":
            reject_segments = None
            
        reject_hostports = routing.routing.get("reject_hostports", "none")
        if reject_hostports == "none":
            reject_hostports = None
        else:
            reject_hostports = str(reject_hostports)
            
        return interface, rt_table, reject_segments, reject_hostports
    elif route_name in configured_vpns:
        vpn = routing.get(route_name)
        return vpn.get("interface"), vpn.get("rt_table"), None, None
    return None, None, None, None


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def direct_vnc_vm_route(request, vm_name):
    if not is_vnc_console_enabled():
        return JsonResponse({"status": "error", "message": "VNC Console is disabled in configuration"}, status=403)

    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "Invalid request method"}, status=405)

    if not LIBVIRT_AVAILABLE:
        return JsonResponse({"status": "error", "message": "Libvirt not available"}, status=500)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        data = {}

    target_route = data.get("route", "none")
    logger.info("direct_vnc_vm_route: Received route change request for VM '%s' to target_route: '%s'", vm_name, target_route)

    # Load machine configuration
    machine = db.view_machine_by_label(vm_name)
    if not machine:
        logger.error("direct_vnc_vm_route: VM '%s' not found in database", vm_name)
        return JsonResponse({"status": "error", "message": f"VM {vm_name} not found"}, status=404)

    logger.info("direct_vnc_vm_route: Found machine in DB: name=%s, ip=%s, interface=%s", machine.name, machine.ip, machine.interface)

    from lib.cuckoo.common.config import Config as CapeConfig
    routing = CapeConfig("routing")
    vpns_raw = routing.vpn.get("vpns", "")
    configured_vpns = [v.strip() for v in vpns_raw.split(",") if v.strip()] if vpns_raw else []

    # Validate target route
    allowed_routes = ["none"]
    if routing.tor.get("enabled", False):
        allowed_routes.append("tor")
    if routing.routing.get("internet", "none") != "none":
        allowed_routes.append("internet")
    if routing.vpn.get("enabled", False):
        allowed_routes.extend(configured_vpns)

    logger.info("direct_vnc_vm_route: Allowed routes based on routing.conf: %s", allowed_routes)

    if target_route not in allowed_routes:
        logger.error("direct_vnc_vm_route: Target route '%s' is not in allowed_routes list", target_route)
        return JsonResponse({"status": "error", "message": f"Route '{target_route}' is not configured or enabled"}, status=400)

    current_route = request.session.get(f"route_{vm_name}", "none")
    logger.info("direct_vnc_vm_route: Current active route in session: '%s'", current_route)
    if current_route == target_route:
        logger.info("direct_vnc_vm_route: Current route is already '%s'. No action needed.", target_route)
        return JsonResponse({"status": "success", "current_route": current_route})

    from utils.router_manager import route_disable, route_enable

    try:
        # Disable previous route
        if current_route != "none":
            interface, rt_table, reject_segments, reject_hostports = get_route_params(
                current_route, routing, configured_vpns
            )
            logger.info("direct_vnc_vm_route: Disabling route '%s' (interface=%s, rt_table=%s)", current_route, interface, rt_table)
            route_disable(current_route, interface, rt_table, machine, reject_segments, reject_hostports)

        # Enable new route
        if target_route != "none":
            interface, rt_table, reject_segments, reject_hostports = get_route_params(
                target_route, routing, configured_vpns
            )
            logger.info("direct_vnc_vm_route: Enabling route '%s' (interface=%s, rt_table=%s)", target_route, interface, rt_table)
            route_enable(target_route, interface, rt_table, machine, reject_segments, reject_hostports)

        # Save route in session
        request.session[f"route_{vm_name}"] = target_route
        logger.info("direct_vnc_vm_route: Successfully updated route for VM '%s' to '%s'", vm_name, target_route)
        return JsonResponse({"status": "success", "current_route": target_route})

    except Exception as e:
        logger.error(f"direct_vnc_vm_route: Failed to change route for VM {vm_name} to {target_route}: {e}")
        return JsonResponse({
            "status": "error",
            "message": str(e),
            "current_route": current_route
        }, status=500)


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def direct_vnc_vm_snapshots_list(request, vm_name):
    if not is_vnc_console_enabled():
        return JsonResponse({"status": "error", "message": "VNC Console is disabled in configuration"}, status=403)

    if not LIBVIRT_AVAILABLE:
        return JsonResponse({"status": "error", "message": "Libvirt not available"}, status=500)

    if machinery not in machinery_available:
        return JsonResponse({"status": "error", "message": f"Machinery type '{machinery}' is not supported"}, status=400)

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
            snapshot_names = dom.snapshotListNames(flags=0)
        except Exception:
            snapshot_names = []

        current_snapshot = None
        try:
            if dom.hasCurrentSnapshot() == 1:
                current_snapshot = dom.currentSnapshot().getName()
        except Exception:
            pass

        if not current_snapshot:
            current_snapshot = request.session.get(f"snapshot_{vm_name}")
            if not current_snapshot:
                machine = db.view_machine_by_label(vm_name) or db.view_machine(vm_name)
                if machine and machine.snapshot:
                    current_snapshot = machine.snapshot

        machine = db.view_machine_by_label(vm_name) or db.view_machine(vm_name)
        default_snapshot = machine.snapshot if (machine and machine.snapshot) else None

        return JsonResponse({
            "status": "success",
            "snapshots": snapshot_names,
            "default_snapshot": default_snapshot,
            "current_snapshot": current_snapshot,
        })
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def direct_vnc_vm_snapshot_create(request, vm_name):
    if not is_vnc_console_enabled():
        return JsonResponse({"status": "error", "message": "VNC Console is disabled in configuration"}, status=403)

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

    snapshot_name = data.get("name")
    description = data.get("description", "")

    if not snapshot_name:
        return JsonResponse({"status": "error", "message": "Snapshot name is required"}, status=400)

    conn = None
    try:
        conn = libvirt.open(machinery_dsn)
        if not conn:
            return JsonResponse({"status": "error", "message": "Could not connect to hypervisor"}, status=500)

        try:
            dom = conn.lookupByName(vm_name)
        except Exception as e:
            return JsonResponse({"status": "error", "message": f"VM {vm_name} not found: {e}"}, status=404)

        state = dom.state(flags=0)
        is_running = state and state[0] == 1
        if not is_running:
            return JsonResponse({"status": "error", "message": "Snapshot creation failed: The VM must be running for a full state capture."}, status=400)

        try:
            dom.snapshotLookupByName(snapshot_name, flags=0)
            return JsonResponse({"status": "error", "message": f"Snapshot '{snapshot_name}' already exists"}, status=400)
        except libvirt.libvirtError:
            pass

        xml = f"""<domainsnapshot>
  <name>{snapshot_name}</name>
  <description>{description}</description>
</domainsnapshot>"""

        flags = 0
        if hasattr(libvirt, "VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC"):
            flags |= libvirt.VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC

        try:
            dom.snapshotCreateXML(xml, flags=flags)
        except Exception as e:
            logger.error("Failed to create snapshot '%s' for VM '%s': %s", snapshot_name, vm_name, e)
            return JsonResponse({"status": "error", "message": f"Failed to create snapshot: {e}"}, status=500)

        machine = db.view_machine_by_label(vm_name)
        if machine:
            try:
                machine.snapshot = snapshot_name
                db.session.commit()
            except Exception as db_err:
                logger.error("Failed to update default snapshot in database for '%s': %s", vm_name, db_err)

        return JsonResponse({"status": "success", "message": f"Snapshot '{snapshot_name}' created successfully"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def direct_vnc_vm_snapshot_delete(request, vm_name):
    if not is_vnc_console_enabled():
        return JsonResponse({"status": "error", "message": "VNC Console is disabled in configuration"}, status=403)

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

    snapshot_name = data.get("name")
    if not snapshot_name:
        return JsonResponse({"status": "error", "message": "Snapshot name is required to delete"}, status=400)

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
            snap = dom.snapshotLookupByName(snapshot_name, flags=0)
        except libvirt.libvirtError:
            return JsonResponse({"status": "error", "message": f"Snapshot '{snapshot_name}' not found"}, status=404)

        try:
            snap.delete(flags=0)
        except Exception as e:
            logger.error("Failed to delete snapshot '%s' for VM '%s': %s", snapshot_name, vm_name, e)
            return JsonResponse({"status": "error", "message": f"Failed to delete snapshot: {e}"}, status=500)

        machine = db.view_machine_by_label(vm_name)
        if machine and machine.snapshot == snapshot_name:
            try:
                try:
                    remaining = dom.snapshotListNames(flags=0)
                except Exception:
                    remaining = []

                if remaining:
                    machine.snapshot = remaining[0]
                else:
                    machine.snapshot = None

                db.session.commit()
            except Exception as db_err:
                logger.error("Failed to update/clear machine snapshot in DB after deletion: %s", db_err)

        return JsonResponse({"status": "success", "message": f"Snapshot '{snapshot_name}' deleted successfully"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


