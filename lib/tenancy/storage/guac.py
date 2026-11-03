"""Distributed interactive-Guacamole worker routing (`guac.py`)."""

from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import quote

log = logging.getLogger(__name__)


def _worker_api_token(token_file: str) -> str:
    try:
        with open(token_file) as f:
            return f.read().strip()
    except Exception:
        return ""


def _bracket(host: Any) -> str:
    text = str(host)
    return f"[{text}]" if ":" in text else text


def _worker_machine_url(worker_ip: str, port: int, cape_task_id: int) -> str:
    return f"http://{_bracket(worker_ip)}:{int(port)}/apiv2/tasks/machine/{int(cape_task_id)}/"


def _libvirt_ssh_dsn(ip: str, ssh_user: str, keyfile: str) -> str:
    return f"qemu+ssh://{ssh_user}@{_bracket(ip)}/system?keyfile={quote(keyfile, safe='/')}&no_verify=1"


def _job_id_for_task(task_id: Any) -> Optional[str]:
    try:
        return f"ui-{int(task_id)}"
    except (TypeError, ValueError):
        return None


def _worker_ip(cfg: Any, task_id: Any) -> Optional[str]:
    from lib.tenancy.storage.job_directory import get_job_directory

    directory = get_job_directory(cfg)
    if directory is None:
        return None
    try:
        job_id = _job_id_for_task(task_id)
        if not job_id:
            return None
        loc = directory.lookup(job_id)
        return loc.worker_ip if loc else None
    except Exception as e:
        log.warning("guac: worker resolution failed for task %s: %s", task_id, e)
        return None


def worker_ip_for_task(task_id: Any) -> Optional[str]:
    from lib.tenancy.storage.config import object_storage_config

    return _worker_ip(object_storage_config(), task_id)


def _worker_machine_body(task_id: Any) -> Optional[dict[str, Any]]:
    from lib.tenancy.storage.config import object_storage_config
    from lib.tenancy.storage.job_directory import get_job_directory

    cfg = object_storage_config()
    directory = get_job_directory(cfg)
    if directory is None:
        return None
    try:
        job_id = _job_id_for_task(task_id)
        if not job_id:
            return None
        loc = directory.lookup(job_id)
        if not loc:
            return None
        worker_ip = loc.worker_ip
        cape_task_id = loc.cape_task_id
        if not worker_ip or cape_task_id is None:
            return None

        import requests

        token = _worker_api_token(cfg.worker_api_token_file)
        headers = {"Authorization": f"Token {token}"} if token else {}
        r = requests.get(
            _worker_machine_url(worker_ip, cfg.worker_api_port, cape_task_id),
            headers=headers,
            timeout=10,
        )
        if r.status_code != 200:
            log.warning(
                "guac: worker %s tasks/machine for task %s returned HTTP %s",
                worker_ip,
                task_id,
                r.status_code,
            )
            return None
        return r.json() or {}
    except Exception as e:
        log.warning("guac: worker VM lookup failed for task %s: %s", task_id, e)
        return None


def worker_vm_for_task(task_id: Any) -> tuple[Optional[str], Optional[str]]:
    body = _worker_machine_body(task_id)
    if not body:
        return (None, None)
    return (body.get("machine") or None, None)


def worker_vnc_port_for_task(task_id: Any) -> Optional[int]:
    body = _worker_machine_body(task_id)
    if not body:
        return None
    vp = body.get("vnc_port")
    try:
        vp = int(vp)
    except (TypeError, ValueError):
        return None
    return vp if vp > 0 else None


def local_vnc_port(vm_label: str, dsn: Optional[str] = None, retries: int = 3) -> Optional[int]:
    try:
        import time
        from xml.etree import ElementTree as ET

        import libvirt
        from lib.cuckoo.common.config import Config

        if not dsn:
            machinery = Config().cuckoo.machinery
            dsn = getattr(Config(machinery), machinery).get("dsn", "qemu:///system")
    except Exception:
        return None
    for _attempt in range(max(1, int(retries or 1))):
        conn = None
        try:
            conn = libvirt.open(dsn)
            if conn:
                dom = conn.lookupByName(vm_label)
                st = dom.state(flags=0)
                if st and st[0] == 1:
                    g = ET.fromstring(dom.XMLDesc(0)).find('./devices/graphics[@type="vnc"]')
                    raw = (g.get("port") if g is not None else "") or ""
                    p = int(raw) if raw.lstrip("-").isdigit() else 0
                    if p > 0:
                        return p
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
        time.sleep(0.5)
    return None


def libvirt_dsn_for_task(task_id: Any, local_dsn: str) -> tuple[str, Optional[str]]:
    from lib.tenancy.storage.config import object_storage_config

    cfg = object_storage_config()
    ip = _worker_ip(cfg, task_id)
    if not ip:
        return (local_dsn, None)
    dsn = _libvirt_ssh_dsn(ip, cfg.worker_ssh_user, cfg.worker_ssh_keyfile)
    return (dsn, ip)
