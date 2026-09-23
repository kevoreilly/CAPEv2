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
    ],
)
def test_fstab_rejects_invalid_hostname(malicious_hostname, tmp_path):
    with (
        patch.object(fstab, "CUCKOO_ROOT", str(tmp_path)),
        patch.object(fstab, "path_write_file") as mock_write,
        patch.object(fstab.subprocess, "check_output") as mock_mount,
    ):
        fstab.dist_conf.NFS.mount_folder = "workers"
        with pytest.raises(ValueError):
            fstab.add_nfs_entry(malicious_hostname, "worker1")
        with pytest.raises(ValueError):
            fstab.remove_nfs_entry(malicious_hostname)
        mock_write.assert_not_called()
        mock_mount.assert_not_called()


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
        fstab.add_nfs_entry("192.168.1.10", "cape-worker-1")

        mock_write.assert_called_once()
        written_fstab = mock_write.call_args[0][1]
        assert f"192.168.1.10:/opt/CAPEv2 {expected_worker_path} nfs" in written_fstab
        mock_mount.assert_called_once_with(["mount", expected_worker_path])
