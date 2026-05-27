import os
import logging
from typing import Any, Dict
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

# Import centralized GCP logic
from lib.cuckoo.common.gcp import GCSUploader, HAVE_GCP, gcp_cfg

# Set up a logger for this module
log = logging.getLogger(__name__)


class GCS(Report):
    """
    Uploads all analysis files to a Google Cloud Storage (GCS) bucket.
    """

    # This Report module is not executed by default
    order = 9999

    def run(self, results: Dict[str, Any]):
        """
        Run the Report module.

        Args:
            results (dict): The analysis results dictionary.
        """
        # Ensure the required library is installed
        if not HAVE_GCP:
            log.error(
                "Failed to run GCS reporting module: the 'google-cloud-storage' "
                "library is not installed. Please run 'poetry install --extras gcp'."
            )
            return

        if self.reprocess:
            return

        tlp = results.get("info", {}).get("tlp")
        analysis_id = results.get("info", {}).get("id")
        custom = results.get("info", {}).get("custom")

        # Prioritize reporting.conf (self.options), then gcp.conf (gcp_cfg)
        exclude_dirs_str = self.options.get("exclude_dirs")
        exclude_files_str = self.options.get("exclude_files")

        if exclude_dirs_str is None:
            exclude_dirs_str = gcp_cfg.reporting.get("exclude_dirs", "") if hasattr(gcp_cfg, "reporting") else ""

        if exclude_files_str is None:
            exclude_files_str = gcp_cfg.reporting.get("exclude_files", "") if hasattr(gcp_cfg, "reporting") else ""

        exclude_dirs = {item.strip() for item in (exclude_dirs_str or "").split(",") if item.strip()}
        exclude_files = {item.strip() for item in (exclude_files_str or "").split(",") if item.strip()}

        bucket_name = self.options.get("bucket_name") or (gcp_cfg.reporting.get("results_bucket") if hasattr(gcp_cfg, "reporting") else None)
        auth_by = self.options.get("auth_by") or gcp_cfg.gcp.get("auth_by", "vm")
        credentials_path_str = self.options.get("credentials_path") or gcp_cfg.gcp.get("service_account_path")

        credentials_path = None
        if credentials_path_str:
            if not os.path.isabs(credentials_path_str):
                credentials_path = os.path.join(CUCKOO_ROOT, credentials_path_str)
            else:
                credentials_path = credentials_path_str

        mode = self.options.get("mode") or (gcp_cfg.reporting.get("mode", "zip") if hasattr(gcp_cfg, "reporting") else "zip")

        try:
            uploader = GCSUploader(bucket_name, auth_by, credentials_path, exclude_dirs, exclude_files, mode)

            if not analysis_id:
                raise CuckooReportError("Could not get analysis ID from results.")

            source_directory = self.analysis_path
            metadata = GCSUploader.parse_custom_string(custom)

            uploader.upload(source_directory, analysis_id, tlp, metadata=metadata)

        except Exception as e:
            raise CuckooReportError(f"Failed to upload report to GCS: {e}") from e
