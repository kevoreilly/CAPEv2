import logging
import os
import subprocess
from urllib.parse import urlparse

from lib.cuckoo.common.config import Config

HAVE_AZURE = False
cfg = Config()
if cfg.cuckoo.machinery == "az":
    try:
        from azure.core.exceptions import AzureError
        from azure.identity import ClientSecretCredential
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.network.models import PacketCapture, PacketCaptureStorageLocation
        from azure.mgmt.storage import StorageManagementClient
        from azure.storage.blob import BlobServiceClient

        HAVE_AZURE = True
    except ImportError:
        HAVE_AZURE = False
        print("Missing machinery-required libraries.")
        print(
            "poetry run python -m pip install azure-identity msrest msrestazure azure-mgmt-compute azure-mgmt-network azure-mgmt-storage azure-storage-blob"
        )

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)


class AzSniffer(Auxiliary):
    def __init__(self):
        super().__init__()
        self.azsniffer_cfg = Config("auxiliary").get("AzSniffer")
        self.enabled = self.azsniffer_cfg.enabled

        if not HAVE_AZURE or not self.enabled:
            return

        self.cfg = Config("az")
        self.az_config = self.cfg.get("az")
        self.capture_name = None
        self.resource_group = self.az_config.resource_group
        self.storage_account = self.az_config.storage_account
        self.vmss_name = self.az_config.vmss_name
        self.location = self.az_config.location
        self.subscription_id = self.az_config.subscription_id
        self.connection_string = self._clean_connection_string(self.az_config.connection_string)
        self.tenant_id = self.az_config.tenant_id
        self.client_id = self.az_config.client_id
        self.client_secret = self.az_config.client_secret

        self.credentials = self._get_credentials()
        self.network_client = NetworkManagementClient(self.credentials, self.subscription_id)
        self.storage_client = StorageManagementClient(self.credentials, self.subscription_id)
        self.blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)
        self.blob_url = None

    def _clean_connection_string(self, connection_string):
        return connection_string.strip('"')

    def _get_credentials(self):
        return ClientSecretCredential(tenant_id=self.tenant_id, client_id=self.client_id, client_secret=self.client_secret)

    def start(self):
        if not self.enabled:
            return
        self.capture_name = f"PacketCapture_{self.task.id}"
        custom_filters = []
        self.create_packet_capture(custom_filters)

    def create_packet_capture(self, custom_filters):
        storage_location = PacketCaptureStorageLocation(
            storage_id=f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Storage/storageAccounts/{self.storage_account}",
            storage_path=f"https://{self.storage_account}.blob.core.windows.net/network-watcher-logs/{self.capture_name}.cap",
        )

        packet_capture = PacketCapture(
            target=f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Compute/virtualMachineScaleSets/{self.vmss_name}",
            storage_location=storage_location,
            time_limit_in_seconds=18000,
            total_bytes_per_session=1073741824,
            filters=custom_filters,
        )

        try:
            poller = self.network_client.packet_captures.begin_create(
                resource_group_name=self.resource_group,
                network_watcher_name=f"NetworkWatcher_{self.location}",
                packet_capture_name=self.capture_name,
                parameters=packet_capture,
            )
            result = poller.result()

            self.blob_url = result.storage_location.storage_path
            log.info(f"Started Azure Network Watcher packet capture: {self.capture_name}")
            log.debug(f"Blob URL for packet capture: {self.blob_url}")
        except AzureError as e:
            log.error(f"Azure error occurred while creating packet capture: {str(e)}")
            raise
        except Exception as e:
            log.error(f"Unexpected error occurred while creating packet capture: {str(e)}")
            raise

    def stop(self):
        if not self.enabled:
            return

        if not self.capture_name:
            log.error("No packet capture to stop")
            return

        self.stop_packet_capture()
        self.download_packet_capture()
        self.delete_packet_capture()

    def stop_packet_capture(self):
        try:
            poller = self.network_client.packet_captures.begin_stop(
                resource_group_name=self.resource_group,
                network_watcher_name=f"NetworkWatcher_{self.location}",
                packet_capture_name=self.capture_name,
            )
            poller.result()
            log.info(f"Stopped Azure Network Watcher packet capture: {self.capture_name}")
        except AzureError as e:
            log.error(f"Azure error occurred while stopping packet capture: {str(e)}")
        except Exception as e:
            log.error(f"Unexpected error occurred while stopping packet capture: {str(e)}")

    def download_packet_capture(self):
        if not self.blob_url:
            log.error("No blob URL available for download")
            return

        primary_output_dir = f"/opt/CAPEv2/storage/analyses/{self.task.id}"
        primary_output_file = os.path.join(primary_output_dir, "dump.cap")
        fallback_output_file = f"/tmp/dump_task_{self.task.id}.cap"

        try:
            parsed_url = urlparse(self.blob_url)
            container_name = parsed_url.path.split("/")[1]
            blob_name = "/".join(parsed_url.path.split("/")[2:]).strip('"')

            blob_client = self.blob_service_client.get_blob_client(container=container_name, blob=blob_name)

            self._download_to_file(blob_client, primary_output_file)
            log.info(f"Downloaded packet capture for task {self.task.id} to {primary_output_file}")
            self.convert_cap_to_pcap(primary_output_file)
        except AzureError as e:
            log.error(f"Azure error occurred while downloading packet capture: {str(e)}")
            self._try_fallback_download(blob_client, fallback_output_file)
        except Exception as e:
            log.error(f"Unexpected error occurred while downloading packet capture: {str(e)}")
            self._try_fallback_download(blob_client, fallback_output_file)

    def _try_fallback_download(self, blob_client, fallback_output_file):
        try:
            self._download_to_file(blob_client, fallback_output_file)
            log.info(f"Downloaded packet capture for task {self.task.id} to fallback location {fallback_output_file}")
            self.convert_cap_to_pcap(fallback_output_file)
        except Exception as e:
            log.error(f"Failed to download packet capture to fallback location: {str(e)}")

    def _download_to_file(self, blob_client, output_file):
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, "wb") as file:
            download_stream = blob_client.download_blob()
            file.write(download_stream.readall())

    def convert_cap_to_pcap(self, cap_file_path):
        output_dir = f"/opt/CAPEv2/storage/analyses/{self.task.id}"
        pcap_file_path = os.path.join(output_dir, "dump.pcap")
        convert_cmd = ["editcap", "-F", "pcap", cap_file_path, pcap_file_path]

        try:
            os.makedirs(output_dir, exist_ok=True)
            subprocess.run(convert_cmd, check=True, capture_output=True, text=True)
            log.info(f"Converted .cap file to .pcap: {pcap_file_path}")
            os.remove(cap_file_path)  # Remove the original .cap file
        except subprocess.CalledProcessError as e:
            log.error(f"Failed to convert .cap file to .pcap: {e.stderr}")
        except OSError as e:
            log.error(f"Failed to create directory or remove .cap file: {e}")

    def delete_packet_capture(self):
        try:
            poller = self.network_client.packet_captures.begin_delete(
                resource_group_name=self.resource_group,
                network_watcher_name=f"NetworkWatcher_{self.location}",
                packet_capture_name=self.capture_name,
            )
            poller.result()
            log.info(f"Deleted Azure Network Watcher packet capture: {self.capture_name}")
        except AzureError as e:
            log.error(f"Azure error occurred while deleting packet capture: {str(e)}")
        except Exception as e:
            log.error(f"Unexpected error occurred while deleting packet capture: {str(e)}")

    def set_task(self, task):
        self.task = task

    def set_machine(self, machine):
        self.machine = machine

    def set_options(self, options):
        self.options = options
