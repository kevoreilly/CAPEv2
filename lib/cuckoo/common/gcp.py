# From doomedraven for GCP with love
import os
import logging
import time
import shutil

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.path_utils import path_exists

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
reporting_conf = Config("reporting")

# GCS Configuration
GCS_ENABLED = reporting_conf.gcs.get("enabled", False) if hasattr(reporting_conf, "gcs") else False
GCS_DELETE_AFTER_UPLOAD = reporting_conf.gcs.get("delete_after_upload", False) if hasattr(reporting_conf, "gcs") else False

gcs_uploader = None
GCSUploader = None
if GCS_ENABLED:
    from modules.reporting.gcs import GCSUploader
    try:
        # Initialize without args to load from reporting.conf
        gcs_uploader = GCSUploader()
    except Exception as e:
        log.error("Failed to initialize GCS Uploader: %s", e)
        GCS_ENABLED = False


def download_from_gcs(gcs_uri, destination_path, logger=None, client=None):
    """
    Downloads a file from GCS.
    gcs_uri: gs://bucket_name/object_name
    """
    if logger is None:
        logger = log

    if not HAVE_GCP:
        logger.error("Google Cloud Storage dependencies not installed. Please run `poetry install --extras gcp` or `pip install google-cloud-storage`")
        return False

    try:
        if not gcs_uri.startswith("gs://"):
            logger.error("Invalid GCS URI: %s", gcs_uri)
            return False

        path_parts = gcs_uri[5:].split("/", 1)
        if len(path_parts) != 2:
            logger.error("Invalid GCS URI: %s", gcs_uri)
            return False

        bucket_name, blob_name = path_parts

        storage_client = client
        own_client = False
        if not storage_client:
            project_id = gcp_cfg.gcp.get("project")
            if project_id and "<project_id>" in project_id:
                project_id = None

            service_account_path = gcp_cfg.gcp.get("service_account_path")

            if service_account_path and os.path.exists(service_account_path):
                storage_client = storage.Client.from_service_account_json(service_account_path)
            else:
                storage_client = storage.Client(project=project_id)
            own_client = True

        try:
            bucket = storage_client.bucket(bucket_name)
            blob = bucket.blob(blob_name)

            logger.info("Downloading %s to %s", gcs_uri, destination_path)
            blob.download_to_filename(destination_path)
            return True
        finally:
            if own_client and hasattr(storage_client, "close"):
                storage_client.close()
    except Exception as e:
        logger.error("Failed to download from GCS %s: %s", gcs_uri, e)
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
        if self.project_id and "<project_id>" not in self.project_id:
            if not os.environ.get("GOOGLE_CLOUD_PROJECT"):
                os.environ["GOOGLE_CLOUD_PROJECT"] = self.project_id
            if not os.environ.get("GCLOUD_PROJECT"):
                os.environ["GCLOUD_PROJECT"] = self.project_id

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


def gcs_replay(task_range):
    if not GCS_ENABLED:
        log.error("GCS is not enabled in reporting.conf")
        return

    from lib.cuckoo.core.database import Database
    from lib.cuckoo.common.constants import CUCKOO_ROOT

    main_db = Database()

    task_ids = []
    try:
        if "-" in task_range:
            start, end = map(int, task_range.split("-"))
            task_ids = list(range(start, end + 1))
        elif "," in task_range:
            task_ids = [int(x) for x in task_range.split(",")]
        else:
            task_ids = [int(task_range)]
    except ValueError:
        log.error("Invalid task range format. Use 'start-end', 'id1,id2', or 'id'.")
        return

    for task_id in task_ids:
        report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))
        if not path_exists(report_path):
            continue

        try:
            with main_db.session.begin():
                task = main_db.view_task(task_id)
                if not task:
                    log.error("Task %d not found in database", task_id)
                    continue

                tlp = task.tlp
                metadata = GCSUploader.parse_custom_string(task.custom)

                samples = main_db.find_sample(task_id=task_id)
                if samples:
                    metadata["sha256"] = samples[0].sample.sha256
                    metadata["md5"] = samples[0].sample.md5
                    metadata["sha1"] = samples[0].sample.sha1

                metadata["task_id"] = task_id

                gcs_upload_report(report_path, task_id, tlp, metadata=metadata)

        except Exception as e:
            log.error("Failed to replay GCS upload for task %d: %s", task_id, e)


def gcs_upload_report(report_path, analysis_id, tlp=None, metadata=None):
    if not GCS_ENABLED:
        return

    try:
        log.info("[GCS] Task %d ==> GCS", analysis_id)
        gcs_uploader.upload(report_path, analysis_id, tlp=tlp, metadata=metadata)

        if GCS_DELETE_AFTER_UPLOAD:
            try:
                shutil.rmtree(report_path)
                log.info("Deleted local report for task %d after GCS upload", analysis_id)
            except Exception as e:
                log.error("Failed to delete local report %s: %s", report_path, e)

    except Exception as e:
        log.error("Failed to upload report to GCS for task %d: %s", analysis_id, e)


def gcs_sync(time_range):
    if not GCS_ENABLED:
        log.error("GCS is not enabled in reporting.conf")
        return

    from lib.cuckoo.common.cleaners_utils import convert_into_time
    from lib.cuckoo.core.database import Database
    from lib.cuckoo.core.data.task import TASK_REPORTED
    from concurrent.futures import ThreadPoolExecutor, as_completed

    main_db = Database()

    try:
        past_time = convert_into_time(time_range)
    except ValueError as e:
        log.error("Invalid time range: %s", e)
        return

    log.info("Fetching tasks from DB completed after %s", past_time)
    with main_db.session.begin():
        # Only check reported tasks as they are the ones supposed to be in GCS
        tasks = main_db.list_tasks(completed_after=past_time, status=TASK_REPORTED)
        db_ids = [t.id for t in tasks]

    if not db_ids:
        log.info("No reported tasks found in DB for the specified time range")
        return

    log.info("Found %d tasks in DB. Checking existence in GCS...", len(db_ids))

    missing_ids = []
    max_workers = 20  # Use a reasonable number of threads for GCS API calls
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_id = {executor.submit(gcs_uploader.check_exists, tid): tid for tid in db_ids}
        for future in as_completed(future_to_id):
            tid = future_to_id[future]
            try:
                if not future.result():
                    missing_ids.append(tid)
            except Exception as e:
                log.error("Error checking GCS existence for task %d: %s", tid, e)

    if not missing_ids:
        log.info("All tasks are already in GCS.")
        return

    log.info("Found %d missing tasks in GCS: %s", len(missing_ids), sorted(missing_ids))
    # Trigger replay for missing IDs
    gcs_replay(",".join(map(str, sorted(missing_ids))))
