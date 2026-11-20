"""Unit tests for installer/cape2.sh config template copying and systemd unit sync."""
from pathlib import Path
import os
import stat
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
CAPE2_SH = REPO_ROOT / "installer" / "cape2.sh"


def _write_exe(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_cape2_sh_bash_syntax_valid():
    res = subprocess.run(["bash", "-n", str(CAPE2_SH)], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr


def test_cape2_sh_copies_env_default_files(tmp_path):
    conf_default = tmp_path / "conf" / "default"
    conf_out = tmp_path / "conf"
    conf_default.mkdir(parents=True)
    (conf_default / "cuckoo.conf.default").write_text("[cuckoo]\n", encoding="utf-8")
    (conf_default / "cape-processor.env.default").write_text("#CAPE_PARALLEL=7\n", encoding="utf-8")

    # Verify installer/cape2.sh uses *.env.default and test the loop logic
    cape2_text = CAPE2_SH.read_text(encoding="utf-8")
    assert "conf/default/*.conf.default conf/default/*.env.default" in cape2_text

    script = (
        "set -euo pipefail\n"
        f"cd {str(tmp_path)!r}\n"
        "for filename in conf/default/*.conf.default conf/default/*.env.default; do\n"
        '    [ -e "$filename" ] || continue\n'
        '    dest="conf/${filename#conf/default/}"\n'
        '    cp -f "./$filename" "./${dest%.default}"\n'
        "done\n"
    )
    subprocess.run(["bash", "-c", script], check=True)
    assert (conf_out / "cuckoo.conf").exists()
    assert (conf_out / "cape-processor.env").read_text(encoding="utf-8") == "#CAPE_PARALLEL=7\n"


def test_sync_installed_systemd_units_migrates_poetry_and_preserves_custom_root(tmp_path):
    cape_root = tmp_path / "custom_cape"
    src_systemd = cape_root / "systemd"
    dest_systemd = tmp_path / "lib_systemd"
    fake_bin = tmp_path / "bin"
    src_systemd.mkdir(parents=True)
    dest_systemd.mkdir(parents=True)
    fake_bin.mkdir(parents=True)

    # Copy real repo unit files as the updated source
    for unit_name in ("cape-processor.service", "cape-rooter.service", "cape-dist.service", "guac-web.service"):
        (src_systemd / unit_name).write_text(
            (REPO_ROOT / "systemd" / unit_name).read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    # Simulate a pre-5d77816cd stale installed unit that lacked custom/conf/cape-processor.env
    # and had previously been installed with uv and custom CAPE_ROOT
    (dest_systemd / "cape-processor.service").write_text(
        "[Service]\n"
        f"WorkingDirectory={cape_root}\n"
        "Environment=CAPE_PARALLEL=7\n"
        f"EnvironmentFile=-{cape_root}/conf/cape-processor.env\n"
        "ExecStart=/usr/local/bin/uv run python utils/process.py\n",
        encoding="utf-8",
    )
    # Simulate an installed Poetry-based cape-rooter.service and guac-web.service,
    # while cape-dist.service is NOT installed
    (dest_systemd / "cape-rooter.service").write_text(
        "[Service]\n"
        f"WorkingDirectory={cape_root}/utils/\n"
        f"ExecStartPre=/etc/poetry/bin/poetry config cache-dir {cape_root}/.cache/pypoetry\n"
        "ExecStart=/etc/poetry/bin/poetry run python rooter.py -g cape\n",
        encoding="utf-8",
    )
    (dest_systemd / "guac-web.service").write_text(
        "[Service]\n"
        f"WorkingDirectory={cape_root}/web\n"
        "ExecStart=/etc/poetry/bin/poetry run gunicorn --bind 127.0.0.1:8008 web.asgi\n",
        encoding="utf-8",
    )

    systemctl_log = tmp_path / "systemctl.log"
    _write_exe(fake_bin / "sudo", '#!/bin/bash\nexec "$@"\n')
    _write_exe(fake_bin / "systemctl", f'#!/bin/bash\necho "$@" >> "{systemctl_log}"\n')

    # Extract sync_installed_systemd_units from installer/cape2.sh and run it
    script = (
        "set -euo pipefail\n"
        f"CAPE_ROOT={str(cape_root)!r}\n"
        "PYTHON_MGR=/usr/local/bin/uv\n"
        f"SYSTEMD_UNIT_DIR={str(dest_systemd)!r}\n"
        f"eval \"$(awk '/^function sync_installed_systemd_units\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "sync_installed_systemd_units\n"
    )
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    subprocess.run(["bash", "-c", script], env=env, check=True)

    updated_proc = (dest_systemd / "cape-processor.service").read_text(encoding="utf-8")
    assert f"EnvironmentFile=-{cape_root}/custom/conf/cape-processor.env" in updated_proc
    assert "ExecStart=/usr/local/bin/uv run --no-sync python utils/process.py" in updated_proc
    assert "/opt/CAPEv2" not in updated_proc

    updated_rooter = (dest_systemd / "cape-rooter.service").read_text(encoding="utf-8")
    assert "/opt/CAPEv2" not in updated_rooter
    assert "poetry" not in updated_rooter
    assert "ExecStartPre=" not in updated_rooter
    assert "ExecStart=/usr/local/bin/uv run --no-sync python rooter.py -g cape" in updated_rooter

    updated_guac = (dest_systemd / "guac-web.service").read_text(encoding="utf-8")
    assert "/opt/CAPEv2" not in updated_guac
    assert "poetry" not in updated_guac
    assert "ExecStart=/usr/local/bin/uv run --no-sync gunicorn" in updated_guac

    # Uninstalled optional units must not be created during update
    assert not (dest_systemd / "cape-dist.service").exists()
    assert systemctl_log.read_text(encoding="utf-8").strip() == "daemon-reload"


def test_systemd_units_use_uv_without_poetry_and_python_version_pinned():
    assert (REPO_ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.14"

    python_units = [
        "cape.service",
        "cape-processor.service",
        "cape-rooter.service",
        "cape-web.service",
        "cape-dist.service",
        "cape-fstab.service",
        "cape-sigma-update.service",
        "cape-pubsub.service",
        "guac-web.service",
    ]
    for unit_name in python_units:
        text = (REPO_ROOT / "systemd" / unit_name).read_text(encoding="utf-8")
        assert "poetry" not in text, f"{unit_name} still references poetry"
        assert "ExecStart=/usr/local/bin/uv run --no-sync " in text, f"{unit_name} missing uv run --no-sync"
