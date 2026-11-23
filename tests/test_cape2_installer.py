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
    assert "ExecStart=/usr/local/bin/uv run --no-sync granian --interface asgi --ws" in updated_guac
    assert f"EnvironmentFile=-{cape_root}/custom/conf/guac-web.env" in updated_guac

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


def test_web_systemd_units_use_granian_and_drop_daphne_uwsgi():
    cape_web = (REPO_ROOT / "systemd" / "cape-web.service").read_text(encoding="utf-8")
    assert "granian --interface wsgi --no-ws" in cape_web
    assert "--respawn-failed-workers" in cape_web
    assert "--access-log" in cape_web
    assert "ExecReload=/bin/kill -HUP $MAINPID" in cape_web
    assert "GRANIAN_WORKERS_KILL_TIMEOUT=" in cape_web
    assert "runserver_plus" not in cape_web

    guac_web = (REPO_ROOT / "systemd" / "guac-web.service").read_text(encoding="utf-8")
    assert "granian --interface asgi --ws" in guac_web
    assert "--respawn-failed-workers" in guac_web
    assert "--access-log" in guac_web
    assert "ExecReload=/bin/kill -HUP $MAINPID" in guac_web
    assert "GRANIAN_WORKERS_KILL_TIMEOUT=" in guac_web
    assert "gunicorn" not in guac_web

    settings_src = (REPO_ROOT / "web" / "web" / "settings.py").read_text(encoding="utf-8")
    assert '"daphne"' not in settings_src
    assert not (REPO_ROOT / "uwsgi").exists()
    assert (REPO_ROOT / "nginx" / "cape.conf").exists()
    assert (REPO_ROOT / "conf" / "default" / "cape-web.env.default").exists()
    assert (REPO_ROOT / "conf" / "default" / "guac-web.env.default").exists()
    assert "conf/*.env" in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    cape2_src = (REPO_ROOT / "installer" / "cape2.sh").read_text(encoding="utf-8")
    assert r"granian.*web\.wsgi|cape-web|" in cape2_src


def test_rewrite_poetry_crontab_stream_handles_paths_and_is_idempotent():
    sample = (
        "# comment with /etc/poetry/bin/poetry run python utils/community.py -waf -cr\n"
        "5 0 */1 * * cd /opt/CAPEv2/utils/ && sudo -u cape /etc/poetry/bin/poetry --directory /opt/CAPEv2/ run python3 community.py -waf -cr && sudo -u cape /etc/poetry/bin/poetry --directory /opt/CAPEv2/ run pip install -U flare-capa && systemctl restart cape-processor 2>/dev/null\n"
        "30 1 * * 0 cd /opt/CAPEv2 && sudo -u cape /home/cape/.local/bin/poetry run python ./utils/cleaners.py --delete-unused-file-data-in-mongo\n"
        "@daily sudo -u cape /etc/poetry/bin/poetry --directory /opt/CAPEv2 run python ./utils/cleaners.py --delete-unused-file-data-in-mongo\n"
        "0 2 * * * cd /opt/CAPEv2 && sudo -u cape /etc/poetry/bin/poetry run python custom_script.py\n"
        "0 3 * * * cd /opt/CAPEv2 && sudo -Hu cape /usr/local/bin/uv run --no-sync python utils/community.py -waf -cr\n"
        "0 4 * * * echo mypoetry run stays intact\n"
    )
    script = (
        "set -euo pipefail\n"
        "CAPE_ROOT=/opt/CAPEv2\n"
        "USER=cape\n"
        "PYTHON_MGR=/usr/local/bin/uv\n"
        "PYTHON_MGR_CMD='run --no-sync'\n"
        "PYTHON_MGR_PIP=pip\n"
        f"eval \"$(awk '/^function rewrite_poetry_crontab_stream\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "rewrite_poetry_crontab_stream\n"
    )
    res = subprocess.run(["bash", "-c", script], input=sample, capture_output=True, text=True, check=True)
    lines = res.stdout.splitlines()
    assert lines[0] == "# comment with /etc/poetry/bin/poetry run python utils/community.py -waf -cr"
    assert lines[1] == (
        "5 0 */1 * * cd /opt/CAPEv2 && sudo -Hu cape /usr/local/bin/uv run --no-sync python utils/community.py -waf -cr"
        " && sudo -Hu cape /usr/local/bin/uv pip install --python /opt/CAPEv2/.venv/bin/python -U flare-capa"
        " && systemctl restart cape-processor 2>/dev/null"
    )
    assert lines[2] == (
        "30 1 * * 0 cd /opt/CAPEv2 && sudo -Hu cape /usr/local/bin/uv run --no-sync python ./utils/cleaners.py"
        " --delete-unused-file-data-in-mongo"
    )
    assert lines[3] == (
        "@daily cd /opt/CAPEv2 && sudo -Hu cape /usr/local/bin/uv run --no-sync python ./utils/cleaners.py"
        " --delete-unused-file-data-in-mongo"
    )
    # Custom user cron jobs and already-migrated lines must stay untouched
    assert lines[4] == "0 2 * * * cd /opt/CAPEv2 && sudo -u cape /etc/poetry/bin/poetry run python custom_script.py"
    assert lines[5] == "0 3 * * * cd /opt/CAPEv2 && sudo -Hu cape /usr/local/bin/uv run --no-sync python utils/community.py -waf -cr"
    assert lines[6] == "0 4 * * * echo mypoetry run stays intact"

    # Re-running on already-migrated output must be a no-op
    res2 = subprocess.run(["bash", "-c", script], input=res.stdout, capture_output=True, text=True, check=True)
    assert res2.stdout == res.stdout


def test_install_libvirt_has_no_broken_comment_and_uses_pkg_config(tmp_path):
    cape_root = tmp_path / "CAPEv2"
    cape_root.mkdir()
    pc_dir = tmp_path / "pkgconfig"
    pc_dir.mkdir()
    (pc_dir / "libvirt.pc").write_text("Name: libvirt\nVersion: 11.9.0\n", encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    uv_log = tmp_path / "uv.log"
    _write_exe(
        fake_bin / "sudo",
        '#!/bin/bash\nwhile [ $# -gt 0 ]; do case "$1" in -Hu|-u) shift 2 ;; -H) shift ;; *) break ;; esac; done\nexec "$@"\n',
    )
    _write_exe(fake_bin / "pkg-config", f'#!/bin/bash\necho "{pc_dir}"\n')
    _write_exe(fake_bin / "uv", f'#!/bin/bash\necho "PKG_CONFIG_PATH=$PKG_CONFIG_PATH ARGS=$*" >> "{uv_log}"\n')

    script = (
        "set -euo pipefail\n"
        f"CAPE_ROOT={str(cape_root)!r}\n"
        "USER=cape\n"
        "LIB_VERSION=11.9.0\n"
        "UV_PYTHON_DIR=/usr/local/share/uv/python\n"
        f"PYTHON_MGR={str(fake_bin / 'uv')!r}\n"
        "PYTHON_MGR_PIP=pip\n"
        f"PKG_CONFIG_PATH={str(pc_dir)!r}\n"
        f"eval \"$(awk '/^function install_libvirt\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "install_libvirt\n"
    )
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    res = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=True)
    assert "No such file or directory" not in res.stderr
    logged = uv_log.read_text(encoding="utf-8")
    assert f"PKG_CONFIG_PATH={pc_dir}" in logged
    assert f"pip install --python {cape_root}/.venv/bin/python libvirt-python==11.9.0" in logged


def test_migrate_to_uv_installs_yara_x_and_seeds_env_files(tmp_path):
    cape_root = tmp_path / "CAPEv2"
    (cape_root / "conf" / "default").mkdir(parents=True)
    (cape_root / "systemd").mkdir(parents=True)
    (cape_root / "pyproject.toml").write_text("[project]\nname = 'CAPEv2'\n", encoding="utf-8")
    (cape_root / "conf" / "default" / "cape-web.env.default").write_text("#GRANIAN_PORT=8000\n", encoding="utf-8")
    (cape_root / "systemd" / "cape-web.service").write_text(
        (REPO_ROOT / "systemd" / "cape-web.service").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    dest_systemd = tmp_path / "systemd_dest"
    dest_systemd.mkdir()
    (dest_systemd / "cape-web.service").write_text(
        "[Service]\nExecStart=/etc/poetry/bin/poetry run python manage.py runserver_plus\n",
        encoding="utf-8",
    )

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    uv_log = tmp_path / "uv.log"
    systemctl_log = tmp_path / "systemctl.log"
    _write_exe(
        fake_bin / "sudo",
        '#!/bin/bash\nwhile [ $# -gt 0 ]; do case "$1" in -Hu|-u) shift 2 ;; -H) shift ;; *) break ;; esac; done\nexec "$@"\n',
    )
    _write_exe(fake_bin / "chown", "#!/bin/bash\nexit 0\n")
    _write_exe(fake_bin / "crontab", "#!/bin/bash\nexit 1\n")
    _write_exe(
        fake_bin / "systemctl",
        f'#!/bin/bash\necho "$@" >> "{systemctl_log}"\n'
        'if [ "$1" = "list-unit-files" ]; then echo "cape-web.service enabled"; fi\n',
    )
    _write_exe(fake_bin / "uv", f'#!/bin/bash\necho "$*" >> "{uv_log}"\n')

    script = (
        "set -euo pipefail\n"
        f"CAPE_ROOT={str(cape_root)!r}\n"
        f"FREEZE_FILE={str(tmp_path / 'poetry-freeze.txt')!r}\n"
        "USER=cape\n"
        "DISABLE_LIBVIRT=1\n"
        "UV_PYTHON_VERSION=3.14\n"
        f"UV_PYTHON_DIR={str(tmp_path / 'uv_py')!r}\n"
        f"PYTHON_MGR={str(fake_bin / 'uv')!r}\n"
        "PYTHON_MGR_CMD='run --no-sync'\n"
        "PYTHON_MGR_PIP=pip\n"
        "PYTHON_MGR_INSTALL_PYPROJECT='sync --locked --no-install-project --inexact --python 3.14'\n"
        f"SYSTEMD_UNIT_DIR={str(dest_systemd)!r}\n"
        "install_uv_and_python() { mkdir -p \"$UV_PYTHON_DIR\"; }\n"
        f"eval \"$(awk '/^function seed_default_env_files\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        f"eval \"$(awk '/^function sync_installed_systemd_units\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        f"eval \"$(awk '/^function rewrite_poetry_crontab_stream\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        f"eval \"$(awk '/^function migrate_to_uv\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "migrate_to_uv\n"
    )
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=True)

    uv_calls = uv_log.read_text(encoding="utf-8")
    assert f"venv --python 3.14 --allow-existing {cape_root}/.venv" in uv_calls
    assert "sync --locked --no-install-project --inexact --python 3.14" in uv_calls
    assert f"pip install --python {cape_root}/.venv/bin/python yara-x" in uv_calls
    assert "yara-python" not in uv_calls
    assert (cape_root / "conf" / "cape-web.env").read_text(encoding="utf-8") == "#GRANIAN_PORT=8000\n"
    assert "granian --interface wsgi" in (dest_systemd / "cape-web.service").read_text(encoding="utf-8")
    assert "start cape-web.service" in systemctl_log.read_text(encoding="utf-8")


def test_set_python_mgr_preserves_custom_override():
    script = (
        "set -euo pipefail\n"
        "UV_PYTHON_VERSION=3.14\n"
        f"eval \"$(awk '/^set_python_mgr\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "PYTHON_MGR=/custom/bin/uv\n"
        "set_python_mgr\n"
        'echo "custom=$PYTHON_MGR"\n'
        "unset PYTHON_MGR\n"
        "set_python_mgr\n"
        'echo "default=$PYTHON_MGR"\n'
    )
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert res.stdout.splitlines() == ["custom=/custom/bin/uv", "default=/usr/local/bin/uv"]


def test_sync_installed_systemd_units_backs_up_changed_unit_and_skips_unchanged(tmp_path):
    cape_root = tmp_path / "CAPEv2"
    src_systemd = cape_root / "systemd"
    dest_systemd = tmp_path / "etc_systemd"
    fake_bin = tmp_path / "bin"
    src_systemd.mkdir(parents=True)
    dest_systemd.mkdir(parents=True)
    fake_bin.mkdir(parents=True)

    (src_systemd / "cape.service").write_text(
        (REPO_ROOT / "systemd" / "cape.service").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    original_custom_unit = "[Service]\nExecStart=/custom/override\n"
    (dest_systemd / "cape.service").write_text(original_custom_unit, encoding="utf-8")

    systemctl_log = tmp_path / "systemctl.log"
    _write_exe(fake_bin / "sudo", '#!/bin/bash\nexec "$@"\n')
    _write_exe(fake_bin / "systemctl", f'#!/bin/bash\necho "$@" >> "{systemctl_log}"\n')

    script = (
        "set -euo pipefail\n"
        f"CAPE_ROOT={str(cape_root)!r}\n"
        "PYTHON_MGR=/usr/local/bin/uv\n"
        f"SYSTEMD_UNIT_DIR={str(dest_systemd)!r}\n"
        "SYSTEMD_BACKUP_EXISTING=1\n"
        f"eval \"$(awk '/^function sync_installed_systemd_units\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "sync_installed_systemd_units\n"
    )
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    subprocess.run(["bash", "-c", script], env=env, check=True)

    assert (dest_systemd / "cape.service.bak").read_text(encoding="utf-8") == original_custom_unit
    assert systemctl_log.read_text(encoding="utf-8").splitlines() == ["daemon-reload"]

    # Second run with identical rendered unit must not overwrite or reload
    subprocess.run(["bash", "-c", script], env=env, check=True)
    assert systemctl_log.read_text(encoding="utf-8").splitlines() == ["daemon-reload"]


def test_update_prunes_venv_pyc_and_seeds_env_files(tmp_path):
    cape_root = tmp_path / "CAPEv2"
    (cape_root / "conf" / "default").mkdir(parents=True)
    (cape_root / "systemd").mkdir(parents=True)
    (cape_root / ".venv" / "lib" / "pkg").mkdir(parents=True)
    (cape_root / "lib").mkdir(parents=True)
    (cape_root / "conf" / "default" / "cape-web.env.default").write_text("#DEFAULT\n", encoding="utf-8")
    (cape_root / "conf" / "default" / "guac-web.env.default").write_text("#GUAC\n", encoding="utf-8")
    (cape_root / "conf" / "guac-web.env").write_text("GRANIAN_PORT=9999\n", encoding="utf-8")
    (cape_root / "lib" / "stale.pyc").write_bytes(b"pyc")
    (cape_root / ".venv" / "lib" / "pkg" / "keep.pyc").write_bytes(b"venv-pyc")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_exe(
        fake_bin / "sudo",
        '#!/bin/bash\nwhile [ $# -gt 0 ]; do case "$1" in -Hu|-u) shift 2 ;; -H) shift ;; *) break ;; esac; done\nexec "$@"\n',
    )
    _write_exe(fake_bin / "git", "#!/bin/bash\nexit 0\n")
    _write_exe(fake_bin / "chown", "#!/bin/bash\nexit 0\n")
    systemctl_log = tmp_path / "systemctl.log"
    _write_exe(
        fake_bin / "systemctl",
        f'#!/bin/bash\necho "$@" >> "{systemctl_log}"\n'
        'if [ "$1" = "list-unit-files" ]; then echo "cape-web.service enabled"; fi\n',
    )
    _write_exe(fake_bin / "uv", "#!/bin/bash\nexit 0\n")

    script = (
        "set -euo pipefail\n"
        f"CAPE_ROOT={str(cape_root)!r}\n"
        "USER=cape\n"
        "UV_PYTHON_DIR=/usr/local/share/uv/python\n"
        f"PYTHON_MGR={str(fake_bin / 'uv')!r}\n"
        "PYTHON_MGR_CMD='run --no-sync'\n"
        "PYTHON_MGR_INSTALL_PYPROJECT='sync --locked --no-install-project --inexact --python 3.14'\n"
        f"SYSTEMD_UNIT_DIR={str(tmp_path / 'systemd_empty')!r}\n"
        f"eval \"$(awk '/^function seed_default_env_files\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        f"eval \"$(awk '/^function sync_installed_systemd_units\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        f"eval \"$(awk '/^function update\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "update\n"
    )
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    subprocess.run(["bash", "-c", script], env=env, check=True)

    assert not (cape_root / "lib" / "stale.pyc").exists()
    assert (cape_root / ".venv" / "lib" / "pkg" / "keep.pyc").exists()
    assert (cape_root / "conf" / "cape-web.env").read_text(encoding="utf-8") == "#DEFAULT\n"
    assert (cape_root / "conf" / "guac-web.env").read_text(encoding="utf-8") == "GRANIAN_PORT=9999\n"


def test_root_systemd_units_disable_bytecode_and_installer_uses_sudo_hu():
    for unit_name in ("cape-rooter.service", "cape-fstab.service"):
        unit_text = (REPO_ROOT / "systemd" / unit_name).read_text(encoding="utf-8")
        assert "Environment=PYTHONDONTWRITEBYTECODE=1" in unit_text, f"{unit_name} missing PYTHONDONTWRITEBYTECODE=1"

    cape2_lines = CAPE2_SH.read_text(encoding="utf-8").splitlines()
    for lineno, line in enumerate(cape2_lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        assert not ("sudo -u " in stripped and "PYTHON_MGR" in stripped), (
            f"installer/cape2.sh:{lineno} uses sudo -u without -H with $PYTHON_MGR: {stripped}"
        )

    cape2_src = "\n".join(cape2_lines)
    assert "/usr/bin/systemctl reload-or-restart guac-web" in cape2_src
    assert '[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"; cargo install --path cli' in cape2_src
    assert "apt-get install -y locate" not in cape2_src


def test_install_libvirt_matches_host_pkg_config_version_and_falls_back_to_lte(tmp_path):
    cape_root = tmp_path / "CAPEv2"
    cape_root.mkdir()
    pc_dir = tmp_path / "pkgconfig"
    pc_dir.mkdir()
    (pc_dir / "libvirt.pc").write_text("Name: libvirt\nVersion: 10.0.0\n", encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    uv_log = tmp_path / "uv.log"
    _write_exe(
        fake_bin / "sudo",
        '#!/bin/bash\nwhile [ $# -gt 0 ]; do case "$1" in -Hu|-u) shift 2 ;; -H) shift ;; *) break ;; esac; done\nexec "$@"\n',
    )
    _write_exe(
        fake_bin / "pkg-config",
        '#!/bin/bash\nif [ "$1" = "--modversion" ]; then echo "10.0.0"; else echo ""; fi\n',
    )
    # Fail exact pin to verify fallback uses <=10.0.0 (not unpinned latest).
    _write_exe(
        fake_bin / "uv",
        f'#!/bin/bash\necho "$*" >> "{uv_log}"\n'
        'case "$*" in *libvirt-python==10.0.0*) exit 1 ;; *) exit 0 ;; esac\n',
    )

    script = (
        "set -euo pipefail\n"
        f"CAPE_ROOT={str(cape_root)!r}\n"
        "USER=cape\n"
        "LIB_VERSION=11.9.0\n"
        "UV_PYTHON_DIR=/usr/local/share/uv/python\n"
        f"PYTHON_MGR={str(fake_bin / 'uv')!r}\n"
        "PYTHON_MGR_PIP=pip\n"
        f"PKG_CONFIG_PATH={str(pc_dir)!r}\n"
        f"eval \"$(awk '/^function install_libvirt\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "install_libvirt\n"
    )
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=True)

    calls = uv_log.read_text(encoding="utf-8").splitlines()
    assert calls == [
        f"pip install --python {cape_root}/.venv/bin/python libvirt-python==10.0.0",
        f"pip install --python {cape_root}/.venv/bin/python libvirt-python<=10.0.0",
    ]


def test_migrate_to_uv_reinstalls_batch_deobfuscator_from_poetry_freeze(tmp_path):
    cape_root = tmp_path / "CAPEv2"
    (cape_root / "conf" / "default").mkdir(parents=True)
    (cape_root / "systemd").mkdir(parents=True)
    (cape_root / "pyproject.toml").write_text("[project]\nname = 'CAPEv2'\n", encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    uv_log = tmp_path / "uv.log"
    _write_exe(
        fake_bin / "sudo",
        '#!/bin/bash\nwhile [ $# -gt 0 ]; do case "$1" in -Hu|-u) shift 2 ;; -H) shift ;; *) break ;; esac; done\nexec "$@"\n',
    )
    _write_exe(fake_bin / "chown", "#!/bin/bash\nexit 0\n")
    _write_exe(fake_bin / "crontab", "#!/bin/bash\nexit 1\n")
    _write_exe(fake_bin / "systemctl", "#!/bin/bash\nexit 0\n")
    _write_exe(fake_bin / "poetry", '#!/bin/bash\necho "batch-deobfuscator==0.1.0"\n')
    _write_exe(fake_bin / "uv", f'#!/bin/bash\necho "$*" >> "{uv_log}"\n')

    script = (
        "set -euo pipefail\n"
        f"CAPE_ROOT={str(cape_root)!r}\n"
        f"FREEZE_FILE={str(tmp_path / 'poetry-freeze.txt')!r}\n"
        "USER=cape\n"
        "DISABLE_LIBVIRT=1\n"
        "UV_PYTHON_VERSION=3.14\n"
        f"UV_PYTHON_DIR={str(tmp_path / 'uv_py')!r}\n"
        f"PYTHON_MGR={str(fake_bin / 'uv')!r}\n"
        "PYTHON_MGR_CMD='run --no-sync'\n"
        "PYTHON_MGR_PIP=pip\n"
        "PYTHON_MGR_INSTALL_PYPROJECT='sync --locked --no-install-project --inexact --python 3.14'\n"
        f"SYSTEMD_UNIT_DIR={str(tmp_path / 'systemd_empty')!r}\n"
        "install_uv_and_python() { mkdir -p \"$UV_PYTHON_DIR\"; }\n"
        f"eval \"$(awk '/^function seed_default_env_files\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        f"eval \"$(awk '/^function sync_installed_systemd_units\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        f"eval \"$(awk '/^function rewrite_poetry_crontab_stream\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        f"eval \"$(awk '/^function migrate_to_uv\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "migrate_to_uv\n"
    )
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=True)

    uv_calls = uv_log.read_text(encoding="utf-8")
    assert (
        f"pip install --python {cape_root}/.venv/bin/python -U git+https://github.com/DissectMalware/batch_deobfuscator"
        in uv_calls
    )


def test_install_libvirt_discovers_usr_lib64_pkgconfig(tmp_path):
    cape_root = tmp_path / "CAPEv2"
    cape_root.mkdir()
    sysroot = tmp_path / "sysroot"
    pc_dir = sysroot / "usr" / "lib64" / "pkgconfig"
    pc_dir.mkdir(parents=True)
    (pc_dir / "libvirt.pc").write_text("Name: libvirt\nVersion: 11.10.0\n", encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    uv_log = tmp_path / "uv.log"
    _write_exe(
        fake_bin / "sudo",
        '#!/bin/bash\nwhile [ $# -gt 0 ]; do case "$1" in -Hu|-u) shift 2 ;; -H) shift ;; *) break ;; esac; done\nexec "$@"\n',
    )
    _write_exe(
        fake_bin / "pkg-config",
        '#!/bin/bash\nif [ "$1" = "--modversion" ]; then echo "11.10.0"; else echo ""; fi\n',
    )
    _write_exe(fake_bin / "uv", f'#!/bin/bash\necho "PKG_CONFIG_PATH=$PKG_CONFIG_PATH ARGS=$*" >> "{uv_log}"\n')

    script = (
        "set -euo pipefail\n"
        f"CAPE_ROOT={str(cape_root)!r}\n"
        "USER=cape\n"
        "LIB_VERSION=11.9.0\n"
        "UV_PYTHON_DIR=/usr/local/share/uv/python\n"
        f"PYTHON_MGR={str(fake_bin / 'uv')!r}\n"
        "PYTHON_MGR_PIP=pip\n"
        "PKG_CONFIG_PATH=''\n"
        f"LIBVIRT_PC_PREFIX={str(sysroot)!r}\n"
        f"eval \"$(awk '/^function install_libvirt\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "install_libvirt\n"
    )
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
    subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=True)

    logged = uv_log.read_text(encoding="utf-8").strip()
    assert f"PKG_CONFIG_PATH={pc_dir}" in logged
    assert f"pip install --python {cape_root}/.venv/bin/python libvirt-python==11.10.0" in logged


def test_install_libvirt_discovers_custom_virsh_prefix_and_find_lib64(tmp_path):
    cape_root = tmp_path / "CAPEv2"
    cape_root.mkdir()
    opt_prefix = tmp_path / "opt_libvirt"
    opt_bin = opt_prefix / "bin"
    opt_pc_dir = opt_prefix / "lib64" / "pkgconfig"
    opt_bin.mkdir(parents=True)
    opt_pc_dir.mkdir(parents=True)
    _write_exe(opt_bin / "virsh", "#!/bin/bash\necho 12.6.0\n")
    (opt_pc_dir / "libvirt.pc").write_text("Name: libvirt\nVersion: 12.6.0\n", encoding="utf-8")

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    uv_log = tmp_path / "uv.log"
    _write_exe(
        fake_bin / "sudo",
        '#!/bin/bash\nwhile [ $# -gt 0 ]; do case "$1" in -Hu|-u) shift 2 ;; -H) shift ;; *) break ;; esac; done\nexec "$@"\n',
    )
    _write_exe(
        fake_bin / "pkg-config",
        '#!/bin/bash\nif [ "$1" = "--modversion" ]; then echo "12.6.0"; else echo ""; fi\n',
    )
    _write_exe(fake_bin / "uv", f'#!/bin/bash\necho "PKG_CONFIG_PATH=$PKG_CONFIG_PATH ARGS=$*" >> "{uv_log}"\n')

    script = (
        "set -euo pipefail\n"
        f"CAPE_ROOT={str(cape_root)!r}\n"
        "USER=cape\n"
        "LIB_VERSION=11.9.0\n"
        "UV_PYTHON_DIR=/usr/local/share/uv/python\n"
        f"PYTHON_MGR={str(fake_bin / 'uv')!r}\n"
        "PYTHON_MGR_PIP=pip\n"
        "PKG_CONFIG_PATH=''\n"
        f"eval \"$(awk '/^function install_libvirt\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "install_libvirt\n"
    )
    env = dict(os.environ)
    env["PATH"] = f"{opt_bin}:{fake_bin}:{env.get('PATH', '')}"
    subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, check=True)

    logged = uv_log.read_text(encoding="utf-8").strip()
    assert f"PKG_CONFIG_PATH={opt_pc_dir}" in logged
    assert f"pip install --python {cape_root}/.venv/bin/python libvirt-python==12.6.0" in logged

    # Also verify find fallback under sysroot/usr/lib64 when /usr/local/lib64 does not exist (pipefail-safe)
    sysroot = tmp_path / "find_sysroot"
    nested_pc_dir = sysroot / "usr" / "lib64" / "custom" / "pkgconfig"
    nested_pc_dir.mkdir(parents=True)
    (nested_pc_dir / "libvirt.pc").write_text("Name: libvirt\nVersion: 12.6.0\n", encoding="utf-8")
    uv_log.unlink()

    script_find = (
        "set -euo pipefail\n"
        f"CAPE_ROOT={str(cape_root)!r}\n"
        "USER=cape\n"
        "LIB_VERSION=11.9.0\n"
        "UV_PYTHON_DIR=/usr/local/share/uv/python\n"
        f"PYTHON_MGR={str(fake_bin / 'uv')!r}\n"
        "PYTHON_MGR_PIP=pip\n"
        "PKG_CONFIG_PATH=''\n"
        f"LIBVIRT_PC_PREFIX={str(sysroot)!r}\n"
        f"eval \"$(awk '/^function install_libvirt\\(\\)/,/^\\}}/' {str(CAPE2_SH)!r})\"\n"
        "install_libvirt\n"
    )
    subprocess.run(["bash", "-c", script_find], env=env, capture_output=True, text=True, check=True)
    logged_find = uv_log.read_text(encoding="utf-8").strip()
    assert f"PKG_CONFIG_PATH={nested_pc_dir}" in logged_find
    assert f"pip install --python {cape_root}/.venv/bin/python libvirt-python==12.6.0" in logged_find
