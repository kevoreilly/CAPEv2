import logging
import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists, path_get_filename

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload

    HAVE_GOOGLE_CLIENT = True
except ImportError:
    HAVE_GOOGLE_CLIENT = False
    print("Missed google client: poetry run pip install google-api-python-client")

log = logging.getLogger(__name__)


class ReportBackup(Report):
    """Submit reports to external storage."""

    # ensure we run after the reports are generated
    order = 10

    def _get_google_service(self, api_name, api_version, scopes, key_file_location):
        """Get a service that communicates to a Google API.
        Args:
            api_name: The name of the api to connect to.
            api_version: The api version to connect to.
            scopes: A list auth scopes to authorize for the application.
            key_file_location: The path to a valid service account JSON key file.

        Returns:
            A service that is connected to the specified API.
        """
        credentials = service_account.Credentials.from_service_account_file(key_file_location)
        scoped_credentials = credentials.with_scopes(scopes)
        # Build the service object.
        service = build(api_name, api_version, credentials=scoped_credentials)
        return service

    def _backup_to_google_drive(self):
        """Backup files to Google Drive"""

        try:
            # Specify ID of shared Google Drive Folder where reports are uploaded
            folder_id = self.options.get("drive_folder_id")
            if not folder_id:
                log.error("You need to specify Google Drive shared folder in config")
                return

            key_file_location = self.options.get("drive_credentials_location")
            if not key_file_location or not path_exists(os.path.join(CUCKOO_ROOT, key_file_location)):
                log.error("You need to specify path for Google Drive credentials")
                return

            # Authenticate and construct service.
            service = self._get_google_service(
                api_name="drive",
                api_version="v3",
                scopes=["https://www.googleapis.com/auth/drive"],
                key_file_location=os.path.join(CUCKOO_ROOT, key_file_location),
            )
            upload_file_list = [os.path.join(self.reports_path, f) for f in os.listdir(self.reports_path)]

            log.debug("List of reports to be uploaded: %s", str(upload_file_list))

            for item in upload_file_list:
                # Reformat file name for uploads to Google Drive
                report_name = path_get_filename(item)
                base_name, extension = report_name.rsplit(".", 1)
                final_name = f"{base_name}_{self.task['id']}.{extension}"
                file_metadata = {"name": final_name, "parents": [folder_id]}
                media = MediaFileUpload(item)
                file = service.files().create(body=file_metadata, media_body=media, fields="id").execute()
                log.debug("Uploaded Report: %s (%s) as %s", item, file.get("id"), final_name)
        except Exception as e:
            log.error("Unable to upload reports to Google Drive: %s", str(e))

    def run(self, results):
        """Upload report files to external service"""

        if self.options.get("googledrive") and HAVE_GOOGLE_CLIENT:
            self._backup_to_google_drive()
