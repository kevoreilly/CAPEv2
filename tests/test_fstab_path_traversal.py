from unittest.mock import patch
import os
import pytest

from utils import fstab


@pytest.mark.parametrize(
    "malicious_folder",
    [
        "/etc",
        "/etc/cron.d",
        "../../etc",
        "../workers_evil",
        "worker/../../etc",
        ".",
        "..",
        "",
        "-o",
        "worker\nattacker:/opt/CAPEv2 /etc nfs defaults 0 0",
        "worker space",
    ],
)
def test_fstab_rejects_path_traversal_worker_folder(malicious_folder, tmp_path):
    with (
        patch.object(fstab, "CUCKOO_ROOT", str(tmp_path)),
        patch.object(fstab, "path_write_file") as mock_write,
        patch.object(fstab.subprocess, "check_output") as mock_mount,
    ):
        fstab.dist_conf.NFS.mount_folder = "workers"
        with pytest.raises(ValueError):
            fstab.add_nfs_entry("10.0.0.1", malicious_folder)
        mock_write.assert_not_called()
        mock_mount.assert_not_called()


@pytest.mark.parametrize(
    "malicious_hostname",
    [
        "/etc",
        "../../etc",
        "attacker.com /etc nfs defaults 0 0 #",
        "attacker.com\n10.0.0.2:/opt/CAPEv2 /etc",
        "-flag",
        "",
        ".",
        "..",
        "8.8.8.8",
        "1.1.1.1",
        "127.0.0.1",
        "::1",
        "169.254.169.254",
        "0.0.0.0",
        "2001:4860:4860::8888",
    ],
)
def test_fstab_rejects_invalid_or_non_private_hostname(malicious_hostname, tmp_path):
    with (
        patch.object(fstab, "CUCKOO_ROOT", str(tmp_path)),
        patch.object(fstab, "path_write_file") as mock_write,
        patch.object(fstab.subprocess, "check_output") as mock_mount,
    ):
        fstab.dist_conf.NFS.mount_folder = "workers"
        fstab.dist_conf.NFS.allowed_networks = ""
        with pytest.raises(ValueError):
            fstab.add_nfs_entry(malicious_hostname, "worker1")
        with pytest.raises(ValueError):
            fstab.remove_nfs_entry(malicious_hostname)
        mock_write.assert_not_called()
        mock_mount.assert_not_called()


def test_fstab_rejects_domain_resolving_to_public_ip(tmp_path):
    fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 0))]
    with (
        patch.object(fstab, "CUCKOO_ROOT", str(tmp_path)),
        patch.object(fstab.socket, "getaddrinfo", return_value=fake_addrinfo),
        patch.object(fstab, "path_write_file") as mock_write,
        patch.object(fstab.subprocess, "check_output") as mock_mount,
    ):
        fstab.dist_conf.NFS.mount_folder = "workers"
        fstab.dist_conf.NFS.allowed_networks = ""
        with pytest.raises(ValueError, match="non-private IP"):
            fstab.add_nfs_entry("attacker.com", "worker1")
        mock_write.assert_not_called()
        mock_mount.assert_not_called()


def test_fstab_enforces_allowed_networks_cidr(tmp_path):
    workers_dir = tmp_path / "workers"
    workers_dir.mkdir()
    with (
        patch.object(fstab, "CUCKOO_ROOT", str(tmp_path)),
        patch.object(fstab, "path_mount_point", return_value=False),
        patch.object(fstab, "path_read_file", return_value="# /etc/fstab\n"),
        patch.object(fstab, "path_write_file") as mock_write,
        patch.object(fstab.subprocess, "check_output") as mock_mount,
    ):
        fstab.dist_conf.NFS.mount_folder = "workers"
        fstab.dist_conf.NFS.allowed_networks = "10.128.0.0/16, 172.16.10.0/24"

        # Private IP outside allowed_networks is rejected
        with pytest.raises(ValueError, match="outside configured allowed_networks"):
            fstab.add_nfs_entry("192.168.1.10", "cape-worker-1")
        mock_write.assert_not_called()

        # Private IP inside allowed_networks is accepted
        fstab.add_nfs_entry("10.128.1.25", "cape-worker-1")
        mock_write.assert_called_once()
        mock_mount.assert_called_once()


def test_fstab_allows_valid_worker_within_mount_folder(tmp_path):
    workers_dir = tmp_path / "workers"
    workers_dir.mkdir()
    expected_worker_path = os.path.realpath(str(workers_dir / "cape-worker-1"))

    with (
        patch.object(fstab, "CUCKOO_ROOT", str(tmp_path)),
        patch.object(fstab, "path_mount_point", return_value=False),
        patch.object(fstab, "path_read_file", return_value="# /etc/fstab\n"),
        patch.object(fstab, "path_write_file") as mock_write,
        patch.object(fstab.subprocess, "check_output") as mock_mount,
    ):
        fstab.dist_conf.NFS.mount_folder = "workers"
        fstab.dist_conf.NFS.allowed_networks = ""
        fstab.add_nfs_entry("192.168.1.10", "cape-worker-1")

        mock_write.assert_called_once()
        written_fstab = mock_write.call_args[0][1]
        assert f"192.168.1.10:/opt/CAPEv2 {expected_worker_path} nfs" in written_fstab
        mock_mount.assert_called_once_with(["mount", expected_worker_path])
