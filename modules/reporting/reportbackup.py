from googleapiclient.discovery import build
from google.oauth2 import service_account
from googleapiclient.http import MediaFileUpload
import os
import logging
from lib.cuckoo.common.abstracts import Report

log = logging.getLogger(__name__)

class ReportBackup(Report):
    """Saves analysis results in JSON format."""

    # ensure we run after the reports are generated
    order = 10

    def get_service(self, api_name, api_version, scopes, key_file_location):
        """Get a service that communicates to a Google API.
        Args:
            api_name: The name of the api to connect to.
            api_version: The api version to connect to.
            scopes: A list auth scopes to authorize for the application.
            key_file_location: The path to a valid service account JSON key file.

        Returns:
            A service that is connected to the specified API.
        """
        credentials = service_account.Credentials.from_service_account_file(
        key_file_location)
        scoped_credentials = credentials.with_scopes(scopes)
        # Build the service object.
        service = build(api_name, api_version, credentials=scoped_credentials)
        return service

    def run(self, results):
        """Upload report files to a shared Google Drive Folder.
        """
        # Define the auth scopes to request.
        scope = 'https://www.googleapis.com/auth/drive'
                
        try:
            # Specify ID of shared Google Drive Folder where reports are uploaded
            folder_id = self.options.get("folder_id", None)
            # Replace key file with own credentials file (this file should be located in /opt/CAPEv2/utils because the script runs in working directory /opt/CAPEv2/utils)
            key_file_location = self.options.get("credentials_location", None)
            # Authenticate and construct service.
            service = self.get_service(
                api_name='drive',
                api_version='v3',
                scopes=[scope],
                key_file_location=key_file_location)
            upload_file_list = [os.path.join(self.reports_path, f) for f in os.listdir(self.reports_path)]
            log.info("List of reports to be uploaded: " + str(upload_file_list))
            for item in upload_file_list:
                # Reformat file name for uploads to Google Drive
                name = item.split("analyses/")[1].split("/reports/")
                analysis_no = name[0]
                analysis_name = name[1]
                name = analysis_name.split(".")[0]
                extension = analysis_name.split(".")[1]
                final_name = name + analysis_no + "." + extension
                file_metadata = {'name': final_name, 'parents': [folder_id]}
                media = MediaFileUpload(item)
                file = service.files().create(body=file_metadata, media_body=media,
                        fields='id').execute()
                log.info(F'Uploaded Report: {item} ({file.get("id")}) as ' + final_name)
        except Exception:
            log.error('Unable to upload reports to Google Drive: ')