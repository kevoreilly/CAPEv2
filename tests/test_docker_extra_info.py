import os
import json
import pytest
from unittest.mock import MagicMock, patch, mock_open

from lib.cuckoo.common.integrations.file_extra_info import ToolDispatcher, BINARY_TO_TOOL_MAPPING


class TestDockerExtraInfo:
    @patch("lib.cuckoo.common.integrations.file_extra_info.processing_conf")
    def test_dispatcher_init_defaults(self, mock_processing_conf):
        """Test dispatcher initialization with default configuration values."""
        # Setup mock configuration values
        mock_processing_conf.docker_extra_info = MagicMock()
        mock_processing_conf.docker_extra_info.get.side_effect = lambda key, default: {
            "enabled": True,
            "mode": "mounted",
            "sudo_restriction": False,
            "shared_volume_path": "/tmp/cape-external",
            "api_url": "http://127.0.0.1:8000"
        }.get(key, default)

        dispatcher = ToolDispatcher()
        assert dispatcher.enabled is True
        assert dispatcher.mode == "mounted"
        assert dispatcher.sudo_restriction is False
        assert dispatcher.shared_volume_path == "/tmp/cape-external"
        assert dispatcher.api_url == "http://127.0.0.1:8000"

    @patch("lib.cuckoo.common.integrations.file_extra_info.processing_conf")
    @patch("lib.cuckoo.common.integrations.file_extra_info.integration_conf")
    def test_is_container_configured(self, mock_integration_conf, mock_processing_conf):
        """Test container configured checks for various binary paths under normal and hybrid modes."""
        # Enable docker-extra-info globally
        mock_processing_conf.docker_extra_info = MagicMock()
        mock_processing_conf.docker_extra_info.get.side_effect = lambda key, default: {
            "enabled": True,
        }.get(key, default)

        # Mock tool configurations as attributes using getattr-compatible design
        mock_integration_conf.Inno_extract = {"enabled": True, "run_in_docker": True}
        mock_integration_conf.SevenZip_unpack = {"enabled": False, "run_in_docker": True}
        mock_integration_conf.UPX_unpack = {"enabled": True, "run_in_docker": False} # Hybrid: enabled on host, but run_in_docker is false

        mock_processing_conf.die = {"enabled": True, "run_in_docker": True}
        mock_processing_conf.trid = {"enabled": True, "run_in_docker": False} # Hybrid: enabled, but run_in_docker is false

        dispatcher = ToolDispatcher()
        dispatcher.enabled = True

        # Enabled tool (innoextract) configured for Docker -> True
        assert dispatcher.is_container_configured("innoextract") is True
        assert dispatcher.is_container_configured("/usr/bin/innoextract") is True

        # Disabled tool (7z) -> False
        assert dispatcher.is_container_configured("7z") is False

        # Enabled tool (upx) but run_in_docker=False -> False (runs on host!)
        assert dispatcher.is_container_configured("upx") is False

        # Enabled processing tool (die) configured for Docker -> True
        assert dispatcher.is_container_configured("diec") is True

        # Enabled processing tool (trid) but run_in_docker=False -> False (runs on host!)
        assert dispatcher.is_container_configured("trid") is False

        # Non-mapped binary -> False
        assert dispatcher.is_container_configured("ls") is False

    @patch("lib.cuckoo.common.integrations.file_extra_info.shutil.copy2")
    @patch("os.path.isfile", return_value=True)
    @patch("os.path.isdir", return_value=True)
    def test_prepare_paths_for_container(self, mock_isdir, mock_isfile, mock_copy):
        """Test that paths outside the shared volume are copied inside transparently."""
        dispatcher = ToolDispatcher()
        dispatcher.shared_volume_path = "/tmp/cape-external"

        # Mock paths: input file is outside, output directory (tempdir) is inside
        cmd_args = [
            "/usr/bin/innoextract",
            "/tmp/cuckoo-tmp-123/untrusted_sample.bin",
            "--output-dir",
            "/tmp/cape-external/innoextract_abc"
        ]

        # Trigger preparation
        new_args, copied_files = dispatcher._prepare_paths_for_container(cmd_args, "/tmp/cape-external")

        # Verify output paths
        expected_dest_path = "/tmp/cape-external/innoextract_abc/untrusted_sample.bin"
        assert len(copied_files) == 1
        assert copied_files[0] == expected_dest_path
        assert new_args[1] == expected_dest_path
        mock_copy.assert_called_once_with("/tmp/cuckoo-tmp-123/untrusted_sample.bin", expected_dest_path)

    @patch("subprocess.check_output")
    def test_execute_via_restricted_sudo(self, mock_check_output):
        """Verify that sudoers restriction runs 'sudo docker exec' command lines exactly."""
        dispatcher = ToolDispatcher()
        dispatcher.shared_volume_path = "/tmp/cape-external"
        dispatcher.sudo_restriction = True

        mock_check_output.return_value = b"Sudo execution success"

        cmd_args = ["innoextract", "/tmp/cape-external/innoextract_abc/binary"]
        output = dispatcher._execute_via_restricted_sudo("cape-innoextract", cmd_args)

        expected_cmd = ["sudo", "docker", "exec", "-w", "/tmp/cape-external", "cape-innoextract", "innoextract", "/tmp/cape-external/innoextract_abc/binary"]
        mock_check_output.assert_called_once_with(expected_cmd, stderr=-2)  # -2 is subprocess.STDOUT
        assert output == b"Sudo execution success"

    @patch("lib.cuckoo.common.integrations.file_extra_info.HAVE_DOCKER_SDK", True)
    def test_execute_via_sdk_running_container(self):
        """Verify that direct SDK execution triggers container exec_run and auto-start if stopped."""
        dispatcher = ToolDispatcher()
        dispatcher.shared_volume_path = "/tmp/cape-external"

        # Mock the Docker Client & Container
        mock_container = MagicMock()
        mock_container.status = "stopped"
        mock_container.exec_run.return_value = (0, b"SDK execution success")

        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container
        dispatcher.docker_client = mock_client

        cmd_args = ["innoextract", "/tmp/cape-external/innoextract_abc/binary"]
        output = dispatcher._execute_via_sdk_or_subprocess("cape-innoextract", cmd_args)

        # Container should be started first, then exec_run should be triggered
        mock_container.start.assert_called_once()
        mock_container.exec_run.assert_called_once_with(cmd=cmd_args, workdir="/tmp/cape-external")
        assert output == b"SDK execution success"

    @patch("requests.post")
    @patch("os.path.isfile", return_value=True)
    def test_execute_via_api(self, mock_isfile, mock_post):
        """Verify remote API Gateway execution packs files and calls POST endpoints."""
        dispatcher = ToolDispatcher()
        dispatcher.api_url = "http://api-server"
        dispatcher.shared_volume_path = "/tmp/cape-external"

        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/plain"}
        mock_response.content = b"API response success"
        mock_post.return_value = mock_response

        # Mock file open
        m = mock_open(read_data=b"file content")
        with patch("builtins.open", m):
            cmd_args = ["innoextract", "/tmp/cape-external/innoextract_abc/sample.bin"]
            output = dispatcher._execute_via_api("cape-innoextract", cmd_args)

        assert output == b"API response success"
        mock_post.assert_called_once()
        called_args, called_kwargs = mock_post.call_args
        assert called_args[0] == "http://api-server/extract"
        assert called_kwargs["data"]["container_name"] == "cape-innoextract"
        assert "cmd_args" in called_kwargs["data"]
