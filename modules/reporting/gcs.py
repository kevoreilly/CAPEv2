import os
import logging
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

        # Read configuration options from gcs.conf
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

        # --- NEW: Parse the exclusion strings into sets for efficient lookups ---
        # The `if item.strip()` ensures we don't have empty strings from trailing commas
        exclude_dirs = {item.strip() for item in exclude_dirs_str.split(",") if item.strip()}
        exclude_files = {item.strip() for item in exclude_files_str.split(",") if item.strip()}

        if exclude_dirs:
            log.debug("GCS reporting will exclude directories: %s", exclude_dirs)
        if exclude_files:
            log.debug("GCS reporting will exclude files: %s", exclude_files)

        try:
            # --- Authentication ---
            log.debug("Authenticating with Google Cloud Storage...")
            bucket = storage_client.bucket(bucket_name)

            # Check if the bucket exists and is accessible
            if not bucket.exists():
                raise CuckooReportError(
                    "The specified GCS bucket '%s' does not exist or you don't have permission to access it.", bucket_name
                )

            # --- File Upload ---
            # Use the analysis ID as a "folder" in the bucket
            analysis_id = results.get("info", {}).get("id")
            if not analysis_id:
                raise CuckooReportError("Could not get analysis ID from results.")

            log.debug("Uploading files for analysis ID %d to GCS bucket '%s'", analysis_id, bucket_name)

            # self.analysis_path is the path to the analysis results directory
            # e.g., /opt/cape/storage/analyses/123/
            source_directory = self.analysis_path

            for root, dirs, files in os.walk(source_directory):
                # We modify 'dirs' in-place to prevent os.walk from descending into them.
                # This is the most efficient way to skip entire directory trees.
                dirs[:] = [d for d in dirs if d not in exclude_dirs]

                for filename in files:
                    # --- NEW: File Exclusion Logic ---
                    if filename in exclude_files:
                        log.debug("Skipping excluded file: %s", os.path.join(root, filename))
                        continue  # Skip to the next file

                    local_path = os.path.join(root, filename)
                    relative_path = os.path.relpath(local_path, source_directory)
                    blob_name = f"{analysis_id}/{relative_path}"

                    log.debug("Uploading '%s' to '%s'", local_path, blob_name)

                    blob = bucket.blob(blob_name)
                    blob.upload_from_filename(local_path)

            log.info("Successfully uploaded files for analysis %d to GCS.", analysis_id)

        except Exception as e:
            raise CuckooReportError("Failed to upload report to GCS: %s", str(e))
