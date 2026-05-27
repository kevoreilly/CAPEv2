# From doomedraven for GCP with love
import os
import logging
import time
import shutil

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.constants import CUCKOO_ROOT

try:
    from google.api_core.exceptions import Forbidden
    from google.cloud import compute_v1
    from google.cloud import storage
    from google.oauth2 import service_account

    HAVE_GCP = True
except ImportError:
    # pip install --upgrade google-cloud-compute google-cloud-storage
    HAVE_GCP = False

try:
    HAVE_REQUESTS = True
    import requests
except ImportError:
    HAVE_REQUESTS = False

import zipfile
import tempfile

log = logging.getLogger(__name__)

# Initialize standard config
gcp_cfg = Config("gcp")


class GCSUploader:
    """Helper class to upload files to GCS."""

    @staticmethod
    def parse_custom_string(custom_str):
        if not custom_str:
            return {}

        if custom_str.endswith("..."):
            custom_str = custom_str[:-3]
        parts = custom_str.split(",")
        data = {}
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                data[key] = value
        return data

    def __init__(self, bucket_name=None, auth_by=None, credentials_path=None, exclude_dirs=None, exclude_files=None, mode=None):
        if not HAVE_GCP:
            raise ImportError("google-cloud-storage library is missing")

        if not bucket_name:
            bucket_name = gcp_cfg.reporting.get("results_bucket") if hasattr(gcp_cfg, "reporting") else None
            auth_by = gcp_cfg.gcp.get("auth_by", "vm")
            credentials_path = gcp_cfg.gcp.get("service_account_path")
            mode = gcp_cfg.reporting.get("mode", "zip") if hasattr(gcp_cfg, "reporting") else "zip"
            exclude_dirs_str = gcp_cfg.reporting.get("exclude_dirs", "") if hasattr(gcp_cfg, "reporting") else ""
            exclude_files_str = gcp_cfg.reporting.get("exclude_files", "") if hasattr(gcp_cfg, "reporting") else ""

            # Parse exclusion sets
            self.exclude_dirs = {item.strip() for item in (exclude_dirs_str or "").split(",") if item.strip()}
            self.exclude_files = {item.strip() for item in (exclude_files_str or "").split(",") if item.strip()}
        else:
            self.exclude_dirs = exclude_dirs if exclude_dirs else set()
            self.exclude_files = exclude_files if exclude_files else set()

        self.mode = mode or "zip"

        if not bucket_name:
            raise ValueError("GCS bucket_name is not configured.")

        if auth_by == "vm":
            self.storage_client = storage.Client()
        else:
            if credentials_path:
                if not os.path.isabs(credentials_path):
                    credentials_path = os.path.join(CUCKOO_ROOT, credentials_path)
            if not credentials_path or not os.path.exists(credentials_path):
                raise ValueError(f"Invalid credentials path: {credentials_path}")
            credentials = service_account.Credentials.from_service_account_file(credentials_path)
            self.storage_client = storage.Client(credentials=credentials)

        self.bucket = self.storage_client.bucket(bucket_name)

    def _iter_files_to_upload(self, source_directory):
        """Generator that yields files to be uploaded, skipping excluded ones."""
        for root, dirs, files in os.walk(source_directory):
            # Exclude specified directories
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            for filename in files:
                # Exclude specified files
                if filename in self.exclude_files:
                    continue

                local_path = os.path.join(root, filename)
                if not os.path.exists(local_path):
                    continue
                relative_path = os.path.relpath(local_path, source_directory)
                yield local_path, relative_path

    def upload(self, source_directory, analysis_id, tlp=None, metadata=None):
        if self.mode == "zip":
            self.upload_zip_archive(analysis_id, source_directory, tlp=tlp, metadata=metadata)
        else:
            self.upload_files_individually(analysis_id, source_directory, tlp=tlp, metadata=metadata)

    def upload_zip_archive(self, analysis_id, source_directory, tlp=None, metadata=None):
        log.debug("Compressing and uploading files for analysis ID %s to GCS", analysis_id)
        blob_name = f"{analysis_id}_tlp_{tlp}.zip" if tlp else f"{analysis_id}.zip"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip_file:
            tmp_zip_file_name = tmp_zip_file.name
            with zipfile.ZipFile(tmp_zip_file, "w", zipfile.ZIP_DEFLATED) as archive:
                for local_path, relative_path in self._iter_files_to_upload(source_directory):
                    archive.write(local_path, os.path.join(str(analysis_id), relative_path))
        try:
            log.debug("Uploading '%s' to '%s'", tmp_zip_file_name, blob_name)
            blob = self.bucket.blob(blob_name)
            if metadata:
                blob.metadata = metadata
            blob.upload_from_filename(tmp_zip_file_name)
        finally:
            os.unlink(tmp_zip_file_name)
        log.info("Successfully uploaded archive for analysis %s to GCS.", analysis_id)

    def upload_files_individually(self, analysis_id, source_directory, tlp=None, metadata=None):
        log.debug("Uploading files for analysis ID %s to GCS", analysis_id)
        folder_name = f"{analysis_id}_tlp_{tlp}" if tlp else str(analysis_id)

        for local_path, relative_path in self._iter_files_to_upload(source_directory):
            blob_name = f"{folder_name}/{relative_path}"
            # log.debug("Uploading '%s' to '%s'", local_path, blob_name)
            blob = self.bucket.blob(blob_name)
            if metadata:
                blob.metadata = metadata
            blob.upload_from_filename(local_path)

        log.info("Successfully uploaded files for analysis %s to GCS.", analysis_id)

    def check_exists(self, analysis_id):
        """Check if any blobs exist for the given analysis ID."""
        prefix = str(analysis_id)
        blobs = list(self.storage_client.list_blobs(self.bucket, prefix=prefix, max_results=1))
        return len(blobs) > 0


# GCS Configuration
GCS_ENABLED = gcp_cfg.reporting.get("enabled", False) if hasattr(gcp_cfg, "reporting") else False
GCS_DELETE_AFTER_UPLOAD = gcp_cfg.reporting.get("delete_after_upload", False) if hasattr(gcp_cfg, "reporting") else False


gcs_uploader = None
if GCS_ENABLED:
    try:
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
            auth_by = gcp_cfg.gcp.get("auth_by", "vm")
            service_account_path = gcp_cfg.gcp.get("service_account_path")

            if auth_by == "json" and service_account_path:
                if not os.path.isabs(service_account_path):
                    service_account_path = os.path.join(CUCKOO_ROOT, service_account_path)
                if os.path.exists(service_account_path):
                    storage_client = storage.Client.from_service_account_json(service_account_path)

            if not storage_client:
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
        self.project_id = gcp_cfg.gcp.get("project")
        if self.project_id:
            if not os.environ.get("GOOGLE_CLOUD_PROJECT"):
                os.environ["GOOGLE_CLOUD_PROJECT"] = self.project_id
            if not os.environ.get("GCLOUD_PROJECT"):
                os.environ["GCLOUD_PROJECT"] = self.project_id

        zones_str = gcp_cfg.distributed.get("zones") if hasattr(gcp_cfg, "distributed") else ""
        if not zones_str:
            zones_str = gcp_cfg.gcp.get("zone") or ""
        self.zones = [zone.strip() for zone in zones_str.split(",") if zone.strip()]
        self.GCP_BASE_URL = "https://compute.googleapis.com/compute/v1/"

        self.token = gcp_cfg.gcp.get("token")
        self.headers = {
            "X-Goog-User-Project": self.project_id,
            "Authorization": f"Bearer {self.token}",
        }

    def list_instances(self) -> dict:
        """Auto discovery of new servers"""
        servers = {}
        instance_name_pattern = "cape-server"
        if hasattr(gcp_cfg, "distributed"):
            instance_name_pattern = gcp_cfg.distributed.get("instance_name_pattern", "cape-server")
        if self.token:
            for zone in self.zones:
                try:
                    r = requests.get(f"{self.GCP_BASE_URL}projects/{self.project_id}/zones/{zone}/instances", headers=self.headers)
                    for instance in r.json().get("items", []):
                        if not instance["name"].startswith(instance_name_pattern):
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
                    if not instance.name.startswith(instance_name_pattern):
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
        autodiscovery_interval = 600
        if hasattr(gcp_cfg, "distributed"):
            autodiscovery_interval = int(gcp_cfg.distributed.get("autodiscovery_interval", 600))
        while True:
            servers = self.list_instances()
            if not servers:
                time.sleep(autodiscovery_interval)

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

            time.sleep(autodiscovery_interval)


def gcs_replay(task_range):
    if not GCS_ENABLED:
        log.error("GCS is not enabled in reporting.conf")
        return

    from lib.cuckoo.core.database import Database

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


def gcs_refetch_banned(time_range, samples_bucket=None):
    if not HAVE_GCP:
        log.error("Google Cloud Storage dependencies not installed.")
        return

    from lib.cuckoo.common.cleaners_utils import convert_into_time
    from lib.cuckoo.core.database import Database
    from lib.cuckoo.core.data.task import TASK_BANNED, Task
    from utils.submit import submit_file
    from sqlalchemy import select
    import tempfile

    db = Database()
    try:
        past_time = convert_into_time(time_range)
    except ValueError as e:
        log.error("Invalid time range: %s", e)
        return

    if not samples_bucket:
        samples_bucket = gcp_cfg.samples_pubsub.get("samples_bucket") if hasattr(gcp_cfg, "samples_pubsub") else None
        if not samples_bucket:
            # Fallback to the one we saw in logs if not configured
            samples_bucket = "sandbox-samples-unique"
            log.warning("samples_bucket not configured in gcp.conf, using default: %s", samples_bucket)

    log.info("Refetching banned tasks added after %s from bucket %s", past_time, samples_bucket)

    with db.session.begin():
        stmt = select(Task).where(Task.status == TASK_BANNED).where(Task.added_on >= past_time)
        tasks = db.session.scalars(stmt).all()
        task_data = [
            {
                "id": t.id,
                "sample_id": t.sample_id,
                "options": t.options,
                "custom": t.custom,
                "category": t.category,
                "target": t.target,
            }
            for t in tasks
        ]

    if not task_data:
        log.info("No banned tasks found in the given time range.")
        return

    log.info("Found %d banned tasks to refetch.", len(task_data))

    for task in task_data:
        if not task["sample_id"]:
            log.warning("Task %d has no sample associated, skipping", task["id"])
            continue

        with db.session.begin():
            sample = db.view_sample(task["sample_id"])
            if not sample:
                log.warning("Sample for task %d not found in DB", task["id"])
                continue
            sha256 = sample.sha256

        gcs_uri = f"gs://{samples_bucket}/{sha256}"

        # Use CAPE's temp path if available
        tmp_dir = Config().cuckoo.get("tmppath", "/tmp")
        fd, tmp_path = tempfile.mkstemp(dir=tmp_dir)
        os.close(fd)

        task_ids = []
        try:
            if download_from_gcs(gcs_uri, tmp_path):
                log.info("Successfully downloaded %s, resubmitting...", sha256)
                task_ids, extra_details = submit_file(
                    db=db,
                    file_path=tmp_path,
                    options=task["options"],
                    custom=task["custom"],
                    category=task["category"],
                    filename=os.path.basename(task["target"]),
                )
                if task_ids:
                    log.info("Task %d refetched as new task(s): %s", task["id"], task_ids)
                else:
                    log.error("Failed to resubmit %s: %s", sha256, extra_details.get("errors"))
            else:
                log.error("Failed to download %s from %s", sha256, gcs_uri)
        finally:
            # Only delete if submission failed. If it succeeded, CAPE needs the file.
            if not task_ids and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception as e:
                    log.warning("Failed to delete temp file %s: %s", tmp_path, e)
