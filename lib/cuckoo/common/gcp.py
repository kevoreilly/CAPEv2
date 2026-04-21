# From doomedraven for GCP with love
import os
import logging
import time

from lib.cuckoo.common.config import Config

try:
    from google.api_core.exceptions import Forbidden
    from google.cloud import compute_v1
    from google.cloud import storage

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
gcp_cfg = Config("gcp")


def download_from_gcs(gcs_uri, destination_path):
    """
    Downloads a file from GCS.
    gcs_uri: gs://bucket_name/object_name
    """
    if not HAVE_GCP:
        log.error("Google Cloud Storage dependencies not installed. Please run `poetry install --extras gcp` or `pip install google-cloud-storage`")
        return False

    try:
        if not gcs_uri.startswith("gs://"):
            log.error("Invalid GCS URI: %s", gcs_uri)
            return False

        path_parts = gcs_uri[5:].split("/", 1)
        if len(path_parts) != 2:
            log.error("Invalid GCS URI: %s", gcs_uri)
            return False

        bucket_name, blob_name = path_parts

        service_account_path = gcp_cfg.gcp.get("service_account_path")

        if service_account_path and os.path.exists(service_account_path):
            storage_client = storage.Client.from_service_account_json(service_account_path)
        else:
            storage_client = storage.Client()

        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(blob_name)

        log.info("Downloading %s to %s", gcs_uri, destination_path)
        blob.download_to_filename(destination_path)
        return True
    except Exception as e:
        log.error("Failed to download from GCS %s: %s", gcs_uri, e)
        return False

def check_node_up(host: str) -> bool:
    """Auxiliar function for autodiscovery of instances when cluster autoscale"""
    try:
        r = requests.get(f"http://{host}:8000/apiv2/", verify=False, timeout=300)
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
        if self.dist_cfg.GCP.token:
            for zone in self.zones:
                try:
                    r = requests.get(f"{self.GCP_BASE_URL}projects/{self.project_id}/zones/{zone}/instances", headers=self.headers)
                    for instance in r.json().get("items", []):
                        if not instance["name"].startswith(self.dist_cfg.GCP.instance_name):
                            continue
                        ips = [
                            # Need to replace to internal IP not natIP
                            access["natIP"]
                            for net_iface in instance.get("networkInterfaces", [])
                            for access in net_iface.get("accessConfigs", [])
                        ]
                        servers.setdefault(instance["name"], ips)
                except Exception as e:
                    log.exception(e)
        elif HAVE_GCP:
            try:
                instance_client = compute_v1.InstancesClient()
            except Forbidden:
                log.error("You don't have enough priviledges to list instances")
                return servers

            for zone in self.zones:
                instance_list = instance_client.list(project=self.project_id, zone=zone)
                for instance in instance_list.items:
                    if not instance.name.startswith(self.dist_cfg.GCP.instance_name):
                        continue
                    # Public IP
                    # ips = [access.nat_i_p for net_iface in instance.network_interfaces for access in net_iface.access_configs]
                    # Private IP
                    ips = [net_iface.network_i_p for net_iface in instance.network_interfaces]
                    servers.setdefault(instance.name, ips)

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
                                "http://localhost:9003/node",
                                data={"name": name, "url": f"http://{ip}:8000/apiv2/", "enabled": True},
                            )  # -F apikey=apikey
                            if not r.ok:
                                log.error("Can't registger worker with IP: %s. status_code: %d ", ip, r.status_code)
                        except Exception as e:
                            log.exception(e)
                        break
                    except Exception as e:
                        log.exception(e)

            time.sleep(int(self.dist_cfg.GCP.autodiscovery))
