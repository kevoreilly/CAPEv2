import sys
from unittest.mock import MagicMock, patch

# Inject mock modules for Azure SDK to allow importing/instantiating even if the Azure SDK is not installed
azure_core_mock = MagicMock()
azure_mgmt_network_mock = MagicMock()
azure_mgmt_network_models_mock = MagicMock()
azure_identity_mock = MagicMock()
azure_mgmt_storage_mock = MagicMock()
azure_storage_blob_mock = MagicMock()

sys.modules["azure"] = azure_core_mock
sys.modules["azure.core"] = azure_core_mock
sys.modules["azure.core.exceptions"] = azure_core_mock
sys.modules["azure.identity"] = azure_identity_mock
sys.modules["azure.mgmt"] = azure_mgmt_network_mock
sys.modules["azure.mgmt.network"] = azure_mgmt_network_mock
sys.modules["azure.mgmt.network.models"] = azure_mgmt_network_models_mock
sys.modules["azure.mgmt.storage"] = azure_mgmt_storage_mock
sys.modules["azure.storage"] = azure_storage_blob_mock
sys.modules["azure.storage.blob"] = azure_storage_blob_mock

# Mock the specific classes imported from azure.mgmt.network.models
class MockPacketCapture:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

class MockPacketCaptureStorageLocation:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

azure_mgmt_network_models_mock.PacketCapture = MockPacketCapture
azure_mgmt_network_models_mock.PacketCaptureStorageLocation = MockPacketCaptureStorageLocation


# Now we can import AzSniffer safely
from modules.auxiliary.AzSniffer import AzSniffer


class DummyMachine:
    def __init__(self, label):
        self.label = label


@patch("modules.auxiliary.AzSniffer.HAVE_AZURE", True)
@patch("modules.auxiliary.AzSniffer.Config")
def test_az_sniffer_target_resolution(mock_config_class):
    # Set up mock configuration values
    mock_aux_config = MagicMock()
    mock_aux_config.enabled = True

    mock_az_config = MagicMock()
    mock_az_config.resource_group = "my-rg"
    mock_az_config.storage_account = "mystorage"
    mock_az_config.vmss_name = "myvmss"
    mock_az_config.location = "eastus"
    mock_az_config.subscription_id = "sub-123"
    mock_az_config.connection_string = "DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=key;EndpointSuffix=core.windows.net"
    mock_az_config.tenant_id = "tenant-123"
    mock_az_config.client_id = "client-123"
    mock_az_config.client_secret = "secret-123"

    # Route Config() calls to appropriate mocks
    def config_side_effect(name=None):
        if name == "auxiliary":
            mock_inst = MagicMock()
            mock_inst.get.return_value = mock_aux_config
            return mock_inst
        elif name == "az":
            mock_inst = MagicMock()
            mock_inst.get.return_value = mock_az_config
            return mock_inst
        # Default fallback
        mock_inst = MagicMock()
        return mock_inst

    mock_config_class.side_effect = config_side_effect

    # Instantiate AzSniffer
    sniffer = AzSniffer()
    sniffer.task = MagicMock()
    sniffer.task.id = 42
    sniffer.capture_name = "PacketCapture_42"

    # Test Case 1: Target VMSS instance (e.g. label is myvmss_10)
    sniffer.set_machine(DummyMachine("myvmss_10"))
    with patch.object(sniffer.network_client.packet_captures, "begin_create") as mock_begin_create:
        mock_poller = MagicMock()
        mock_result = MagicMock()
        mock_result.storage_location.storage_path = "https://mystorage.blob.core.windows.net/network-watcher-logs/PacketCapture_42.cap"
        mock_poller.result.return_value = mock_result
        mock_begin_create.return_value = mock_poller

        sniffer.create_packet_capture([])

        # Verify that begin_create was called
        mock_begin_create.assert_called_once()
        # Verify the target set on the PacketCapture parameters
        args, kwargs = mock_begin_create.call_args
        packet_capture_param = kwargs.get("parameters") or args[0]  # depending on positional vs kwarg
        if not packet_capture_param and len(args) >= 4:
            packet_capture_param = args[3]

        expected_target = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachineScaleSets/myvmss/virtualMachines/10"
        assert packet_capture_param.target == expected_target

    # Test Case 2: Target Standalone VM (e.g. label is standalone_vm)
    sniffer.set_machine(DummyMachine("standalone_vm"))
    with patch.object(sniffer.network_client.packet_captures, "begin_create") as mock_begin_create:
        mock_poller = MagicMock()
        mock_result = MagicMock()
        mock_result.storage_location.storage_path = "https://mystorage.blob.core.windows.net/network-watcher-logs/PacketCapture_42.cap"
        mock_poller.result.return_value = mock_result
        mock_begin_create.return_value = mock_poller

        sniffer.create_packet_capture([])

        mock_begin_create.assert_called_once()
        args, kwargs = mock_begin_create.call_args
        packet_capture_param = kwargs.get("parameters") or args[3]

        expected_target = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/standalone_vm"
        assert packet_capture_param.target == expected_target


@patch("modules.auxiliary.AzSniffer.HAVE_AZURE", True)
@patch("modules.auxiliary.AzSniffer.Config")
def test_az_sniffer_download_fallback(mock_config_class):
    # Set up mock configuration values
    mock_aux_config = MagicMock()
    mock_aux_config.enabled = True

    mock_az_config = MagicMock()
    mock_az_config.resource_group = "my-rg"
    mock_az_config.storage_account = "mystorage"
    mock_az_config.vmss_name = "myvmss"
    mock_az_config.location = "eastus"
    mock_az_config.subscription_id = "sub-123"
    mock_az_config.connection_string = "DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=key;EndpointSuffix=core.windows.net"
    mock_az_config.tenant_id = "tenant-123"
    mock_az_config.client_id = "client-123"
    mock_az_config.client_secret = "secret-123"

    def config_side_effect(name=None):
        if name == "auxiliary":
            mock_inst = MagicMock()
            mock_inst.get.return_value = mock_aux_config
            return mock_inst
        elif name == "az":
            mock_inst = MagicMock()
            mock_inst.get.return_value = mock_az_config
            return mock_inst
        mock_inst = MagicMock()
        return mock_inst

    mock_config_class.side_effect = config_side_effect

    # Instantiate AzSniffer
    sniffer = AzSniffer()
    sniffer.task = MagicMock()
    sniffer.task.id = 42
    sniffer.capture_name = "PacketCapture_42"
    sniffer.blob_url = "https://mystorage.blob.core.windows.net/network-watcher-logs/PacketCapture_42.cap"

    # Mock the blob service client
    mock_blob_client = MagicMock()
    mock_container_client = MagicMock()

    # Simulate that the direct blob does NOT exist
    mock_blob_client.exists.return_value = False

    # Simulate that there is a matching blob found via container listing
    mock_found_blob = MagicMock()
    mock_found_blob.name = "subscriptions/sub-123/.../PacketCapture_42_20260908.cap"
    mock_container_client.list_blobs.return_value = [mock_found_blob]

    sniffer.blob_service_client.get_blob_client.return_value = mock_blob_client
    sniffer.blob_service_client.get_container_client.return_value = mock_container_client

    with patch.object(sniffer, "_download_to_file") as mock_download, \
         patch.object(sniffer, "convert_cap_to_pcap") as mock_convert:
        sniffer.download_packet_capture()

        # It should have called list_blobs
        mock_container_client.list_blobs.assert_called_once()
        # It should have downloaded using the resolved/matched blob client
        mock_download.assert_called_once()
        mock_convert.assert_called_once()


if __name__ == "__main__":
    print("Running AzSniffer unit tests directly...")
    # Mock Config inside main execution to avoid import errors
    from unittest.mock import patch
    with patch("modules.auxiliary.AzSniffer.Config") as mock_cfg:
        test_az_sniffer_target_resolution(mock_cfg)
        test_az_sniffer_download_fallback(mock_cfg)
    print("All AzSniffer tests PASSED successfully!")
