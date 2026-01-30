import os
import logging
import tempfile
import zipfile
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooReportError

# Set up a logger for this module
log = logging.getLogger(__name__)

try:
    # Import the Google Cloud Storage client library
    from google.cloud import storage
    from google.oauth2 import service_account

    HAVE_GCS = True
except ImportError:
    HAVE_GCS = False


class GCSUploader:
    """Helper class to upload files to GCS."""

    def __init__(self, bucket_name=None, auth_by=None, credentials_path=None, exclude_dirs=None, exclude_files=None, mode=None):
        if not HAVE_GCS:
            raise ImportError("google-cloud-storage library is missing")

        # Load from reporting.conf if parameters are missing
        if not bucket_name:
            cfg = Config("reporting")
            if not cfg.gcs.enabled:
                 # If we are initializing purely for manual usage but config is disabled, we might want to allow it if params are passed.
                 # But if params are missing AND config is disabled/missing, we can't proceed.
                 pass

            bucket_name = cfg.gcs.bucket_name
            auth_by = cfg.gcs.auth_by
            credentials_path_str = cfg.gcs.credentials_path

            if credentials_path_str:
                credentials_path = os.path.join(CUCKOO_ROOT, credentials_path_str)

            exclude_dirs_str = cfg.gcs.get("exclude_dirs", "")
            exclude_files_str = cfg.gcs.get("exclude_files", "")
            mode = cfg.gcs.get("mode", "file")

            # Parse exclusion sets
            self.exclude_dirs = {item.strip() for item in exclude_dirs_str.split(",") if item.strip()}
            self.exclude_files = {item.strip() for item in exclude_files_str.split(",") if item.strip()}
        else:
            self.exclude_dirs = exclude_dirs if exclude_dirs else set()
            self.exclude_files = exclude_files if exclude_files else set()

        self.mode = mode

        if not bucket_name:
             raise ValueError("GCS bucket_name is not configured.")

        if auth_by == "vm":
            self.storage_client = storage.Client()
        else:
            if not credentials_path or not os.path.exists(credentials_path):
                raise ValueError(f"Invalid credentials path: {credentials_path}")
            credentials = service_account.Credentials.from_service_account_file(credentials_path)
            self.storage_client = storage.Client(credentials=credentials)

        self.bucket = self.storage_client.bucket(bucket_name)
        # We check bucket existence lazily or now?
        # dist.py might not want to crash on init if network is flaky, but validation is good.
        # Let's keep validation.
        # Note: bucket.exists() requires permissions.
        # if not self.bucket.exists():
        #    raise ValueError(f"GCS Bucket '{bucket_name}' does not exist or is inaccessible.")

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

    def upload(self, source_directory, analysis_id, tlp=None):
        if self.mode == "zip":
            self.upload_zip_archive(analysis_id, source_directory, tlp=tlp)
        else:
            self.upload_files_individually(analysis_id, source_directory, tlp=tlp)

    def upload_zip_archive(self, analysis_id, source_directory, tlp=None):
        log.debug("Compressing and uploading files for analysis ID %s to GCS", analysis_id)
        blob_name = f"{analysis_id}_tlp_{tlp}.zip" if tlp else f"{analysis_id}.zip"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip_file:
            tmp_zip_file_name = tmp_zip_file.name
            with zipfile.ZipFile(tmp_zip_file, "w", zipfile.ZIP_DEFLATED) as archive:
                for local_path, relative_path in self._iter_files_to_upload(source_directory):
                    archive.write(local_path, relative_path)
        try:
            log.debug("Uploading '%s' to '%s'", tmp_zip_file_name, blob_name)
            blob = self.bucket.blob(blob_name)
            blob.upload_from_filename(tmp_zip_file_name)
        finally:
            os.unlink(tmp_zip_file_name)
        log.info("Successfully uploaded archive for analysis %s to GCS.", analysis_id)

    def upload_files_individually(self, analysis_id, source_directory, tlp=None):
        log.debug("Uploading files for analysis ID %s to GCS", analysis_id)
        folder_name = f"{analysis_id}_tlp_{tlp}" if tlp else str(analysis_id)

        for local_path, relative_path in self._iter_files_to_upload(source_directory):
            blob_name = f"{folder_name}/{relative_path}"
            # log.debug("Uploading '%s' to '%s'", local_path, blob_name)
            blob = self.bucket.blob(blob_name)
            blob.upload_from_filename(local_path)

        log.info("Successfully uploaded files for analysis %s to GCS.", analysis_id)


class GCS(Report):
    """
    Uploads all analysis files to a Google Cloud Storage (GCS) bucket.
    """

    # This Report module is not executed by default
    order = 9999

    def run(self, results):
        """
        Run the Report module.

        Args:
            results (dict): The analysis results dictionary.
        """
        # Ensure the required library is installed
        if not HAVE_GCS:
            log.error(
                "Failed to run GCS reporting module: the 'google-cloud-storage' "
                "library is not installed. Please run 'poetry run pip install google-cloud-storage'."
            )
            return

        tlp = results.get("info", {}).get("tlp")
        analysis_id = results.get("info", {}).get("id")

        # We can now just use the Uploader.
        # But for backward compatibility with overrides in self.options (e.g. per-module config overrides in Cuckoo),
        # we should pass options explicitly if they differ from default config.
        # However, typically reporting.conf is the source.

        # Parse exclusion lists from self.options to respect local module config
        exclude_dirs_str = self.options.get("exclude_dirs", "")
        exclude_files_str = self.options.get("exclude_files", "")
        exclude_dirs = {item.strip() for item in exclude_dirs_str.split(",") if item.strip()}
        exclude_files = {item.strip() for item in exclude_files_str.split(",") if item.strip()}

        # We manually construct to respect self.options
        bucket_name = self.options.get("bucket_name")
        auth_by = self.options.get("auth_by")
        credentials_path_str = self.options.get("credentials_path")
        credentials_path = None
        if credentials_path_str:
             credentials_path = os.path.join(CUCKOO_ROOT, credentials_path_str)
        mode = self.options.get("mode", "file")

        try:
            uploader = GCSUploader(bucket_name, auth_by, credentials_path, exclude_dirs, exclude_files, mode)

            if not analysis_id:
                raise CuckooReportError("Could not get analysis ID from results.")

            source_directory = self.analysis_path

            uploader.upload(source_directory, analysis_id, tlp)

        except Exception as e:
            raise CuckooReportError(f"Failed to upload report to GCS: {e}") from e
