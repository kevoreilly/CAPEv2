from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database

web_cfg = Config("web")


def guac_vnc_console(request):
    """Context processor that exposes VNC Console settings and guests to templates."""
    enabled = web_cfg.guacamole.get("vnc_console_enabled", False)
    if isinstance(enabled, str):
        enabled = enabled.lower() in ("yes", "true", "on", "1")
    if not enabled:
        return {"vnc_console_enabled": False}

    db = Database()
    machines = [machine.label for machine in db.list_machines(include_reserved=True)]
    new_tab = web_cfg.guacamole.get("vnc_console_new_tab", True)

    return {
        "vnc_console_enabled": True,
        "vnc_console_machines": machines,
        "vnc_console_new_tab": new_tab,
    }
