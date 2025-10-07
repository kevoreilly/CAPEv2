import os
import logging
import tempfile
import zipfile
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report
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

        # Read configuration options from gcs.conf and validate them
        bucket_name = self.options.get("bucket_name")
        if not bucket_name:
            raise CuckooReportError("GCS bucket_name is not configured in reporting.conf -> gcs")
        auth_by = self.options.get("auth_by")
        if auth_by == "vm":
            storage_client = storage.Client()
        else:
            credentials_path_str = self.options.get("credentials_path")
            if not credentials_path_str:
                raise CuckooReportError("GCS credentials_path is not configured in reporting.conf -> gcs")

            credentials_path = os.path.join(CUCKOO_ROOT, credentials_path_str)
            if not os.path.isfile(credentials_path):
                raise CuckooReportError(
                    "GCS credentials_path '%s' is invalid or file does not exist in reporting.conf -> gcs", credentials_path
                )

            credentials = service_account.Credentials.from_service_account_file(credentials_path)
            storage_client = storage.Client(credentials=credentials)

        # Read the exclusion lists, defaulting to empty strings
        exclude_dirs_str = self.options.get("exclude_dirs", "")
        exclude_files_str = self.options.get("exclude_files", "")

        # Parse the exclusion strings into sets for efficient lookups
        exclude_dirs = {item.strip() for item in exclude_dirs_str.split(",") if item.strip()}
        exclude_files = {item.strip() for item in exclude_files_str.split(",") if item.strip()}

        if exclude_dirs:
            log.debug("GCS reporting will exclude directories: %s", exclude_dirs)
        if exclude_files:
            log.debug("GCS reporting will exclude files: %s", exclude_files)

        # Get the upload mode, defaulting to 'file' for backward compatibility
        mode = self.options.get("mode", "file")

        try:
            # --- Authentication ---
            log.debug("Authenticating with Google Cloud Storage...")
            bucket = storage_client.bucket(bucket_name)

            # Check if the bucket exists and is accessible
            if not bucket.exists():
                raise CuckooReportError(
                    "The specified GCS bucket '%s' does not exist or you don't have permission to access it.", bucket_name
                )

            analysis_id = results.get("info", {}).get("id")
            if not analysis_id:
                raise CuckooReportError("Could not get analysis ID from results.")

            source_directory = self.analysis_path

            if mode == "zip":
                self.upload_zip_archive(bucket, analysis_id, source_directory, exclude_dirs, exclude_files)
            elif mode == "file":
                self.upload_files_individually(bucket, analysis_id, source_directory, exclude_dirs, exclude_files)
            else:
                raise CuckooReportError("Invalid GCS upload mode specified: %s. Must be 'file' or 'zip'.", mode)

        except Exception as e:
            raise CuckooReportError(f"Failed to upload report to GCS: {e}") from e

    def _iter_files_to_upload(self, source_directory, exclude_dirs, exclude_files):
        """Generator that yields files to be uploaded, skipping excluded ones."""
        for root, dirs, files in os.walk(source_directory):
            # Exclude specified directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for filename in files:
                # Exclude specified files
                if filename in exclude_files:
                    log.debug("Skipping excluded file: %s", os.path.join(root, filename))
                    continue

                local_path = os.path.join(root, filename)
                relative_path = os.path.relpath(local_path, source_directory)
                yield local_path, relative_path

    def upload_zip_archive(self, bucket, analysis_id, source_directory, exclude_dirs, exclude_files):
        """Compresses and uploads the analysis directory as a single zip file."""
        log.debug("Compressing and uploading files for analysis ID %d to GCS bucket '%s'", analysis_id, bucket.name)
        zip_name = "%s.zip" % analysis_id
        blob_name = zip_name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip_file:
            tmp_zip_file_name = tmp_zip_file.name
            with zipfile.ZipFile(tmp_zip_file, "w", zipfile.ZIP_DEFLATED) as archive:
                for local_path, relative_path in self._iter_files_to_upload(source_directory, exclude_dirs, exclude_files):
                    archive.write(local_path, relative_path)

        try:
            log.debug("Uploading '%s' to '%s'", tmp_zip_file_name, blob_name)
            blob = bucket.blob(blob_name)
            blob.upload_from_filename(tmp_zip_file_name)
        finally:
            os.unlink(tmp_zip_file_name)
        log.info("Successfully uploaded archive for analysis %d to GCS.", analysis_id)

    def upload_files_individually(self, bucket, analysis_id, source_directory, exclude_dirs, exclude_files):
        """Uploads analysis files individually to the GCS bucket."""
        log.debug("Uploading files for analysis ID %d to GCS bucket '%s'", analysis_id, bucket.name)
        for local_path, relative_path in self._iter_files_to_upload(source_directory, exclude_dirs, exclude_files):
            blob_name = f"{analysis_id}/{relative_path}"
            log.debug("Uploading '%s' to '%s'", local_path, blob_name)
            blob = bucket.blob(blob_name)
            blob.upload_from_filename(local_path)

        log.info("Successfully uploaded files for analysis %d to GCS.", analysis_id)
