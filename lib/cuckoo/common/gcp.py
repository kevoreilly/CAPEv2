# From doomedraven for GCP with love
import logging
import time

from lib.cuckoo.common.config import Config

try:
    from google.cloud import compute_v1

    HAVE_GCP = True
except ImportError:
    # pip install --upgrade google-cloud-compute
    HAVE_GCP = False

try:
    HAVE_REQUESTS = True
    import requests
except ImportError:
    HAVE_REQUESTS = False

log = logging.getLogger(__name__)


def check_node_up(host: str) -> bool:
    """Auxiliar function for autodiscovery of instances when cluster autoscale"""
    try:
        r = requests.get(f"http://{host}/apiv2/", verify=False, timeout=300)
        if r.ok:
            return True
    except Exception as e:
        log.critical("Possible invalid CAPE node: %s", e)
    return False


class GCP(object):
    def __init__(self) -> None:
        self.dist_cfg = Config("distributed")
        self.project_id = self.dist_cfg.GCP.project_id
        self.zones = [zone.strip() for zone in self.dist_cfg.GCP.zones.split(",")]
        self.GCP_BASE_URL = "https://compute.googleapis.com/compute/v1/"

        self.headers = {
            "X-Goog-User-Project": self.project_id,
            "Authorization": f"Bearer {self.dist_cfg.GCP.token}",
        }

    def list_instances(self) -> dict:
        """Auto discovery of new servers"""
        servers = {}
        if HAVE_GCP:
            instance_client = compute_v1.InstancesClient()
            for zone in self.zones:
                instance_list = instance_client.list(project=self.project_id, zone=zone)
                for instance in instance_list.items:
                    ips = [access.nat_i_p for net_iface in instance.network_interfaces for access in net_iface.access_configs]
                    servers.setdefault(instance.name, ips)

        elif self.dist_cfg.GCP.token:
            for zone in self.zones:
                try:
                    r = requests.get(f"{self.GCP_BASE_URL}projects/{self.project_id}/zones/{zone}/instances", headers=self.headers)
                    for instance in r.json().get("items", []):
                        ips = [
                            access["natIP"]
                            for net_iface in instance.get("networkInterfaces", [])
                            for access in net_iface.get("accessConfigs", [])
                        ]
                        servers.setdefault(instance["name"], ips)
                except Exception as e:
                    log.error(e, exc_info=True)
        else:
            log.error("Install google-cloud-compute client or provide GCP token in config.")

        return servers

    def autodiscovery(self):

        while True:
            servers = self.list_instances()
            if not servers:
                time.sleep(600)

            for name, ips in servers.items():
                for ip in ips:
                    log.debug("Checking server: %s with IP: %s", name, ip)
                    try:
                        up = check_node_up(ip)
                        if not up:
                            continue
                        try:
                            r = requests.post(
                                "http://localhost:9003/node", data={"name": name, "url": f"http://{ip}:8000/apiv2/"}
                            )  # -F apikey=apikey
                            if r.ok:
                                log.info("New worker with IP: %s registered", ip)
                            else:
                                log.error("Can't registger worker with IP: %s. status_code: %d ", ip, r.status_code)
                        except Exception as e:
                            log.error(e, exc_info=True)
                        break
                    except Exception as e:
                        log.error(e, exc_info=True)

            time.sleep(int(self.dist_cfg.GCP.autodiscovery))
