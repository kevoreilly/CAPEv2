from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
import sys

from django.conf import settings


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_static_root_disjoint_from_staticfiles_dirs_and_matches_service_and_nginx():
    static_root = Path(settings.STATIC_ROOT).resolve()
    expected_root = (REPO_ROOT / "web" / "static_collected").resolve()
    assert static_root == expected_root

    static_dirs = {Path(d).resolve() for d in settings.STATICFILES_DIRS}
    assert static_root not in static_dirs
    assert (REPO_ROOT / "web" / "static").resolve() in static_dirs

    cape_web = (REPO_ROOT / "systemd" / "cape-web.service").read_text(encoding="utf-8")
    assert "ExecStartPre=/bin/mkdir -p /opt/CAPEv2/web/static_collected" in cape_web
    assert "ExecStartPre=/usr/local/bin/uv run --no-sync python manage.py collectstatic --noinput" in cape_web
    assert "--static-path-mount /opt/CAPEv2/web/static_collected" in cape_web

    nginx_conf = (REPO_ROOT / "nginx" / "cape.conf").read_text(encoding="utf-8")
    assert "alias /opt/CAPEv2/web/static_collected/;" in nginx_conf

    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "web/static_collected/" in gitignore


def test_guac_settings_does_not_override_granian_loggers():
    guac_settings_src = (REPO_ROOT / "web" / "web" / "guac_settings.py").read_text(encoding="utf-8")
    assert "guac-granian.log" not in guac_settings_src
    assert '"_granian"' not in guac_settings_src
    assert '"granian.access"' not in guac_settings_src


def test_secret_key_atomic_generation_consistent_across_concurrent_workers(tmp_path):
    """Concurrent multi-worker imports of settings/guac_settings must converge on one SECRET_KEY."""
    for filename in ("settings.py", "guac_settings.py"):
        src = (REPO_ROOT / "web" / "web" / filename).read_text(encoding="utf-8")
        marker = "try:\n    from .secret_key import SECRET_KEY  # noqa: F401\n"
        start = src.index(marker)
        end_marker = "    from .secret_key import SECRET_KEY  # noqa: F401\n"
        end = src.index(end_marker, start + len(marker)) + len(end_marker)
        snippet = "from contextlib import suppress\nimport os\n" + src[start:end]

        pkg_dir = tmp_path / filename.replace(".py", "") / "pkg"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
        (pkg_dir / "loader.py").write_text(snippet, encoding="utf-8")

        def _boot(_idx: int) -> str:
            res = subprocess.run(
                [sys.executable, "-c", "import pkg.loader; print(pkg.loader.SECRET_KEY)"],
                cwd=str(pkg_dir.parent),
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            return res.stdout.strip()

        with ThreadPoolExecutor(max_workers=6) as pool:
            keys = list(pool.map(_boot, range(6)))

        assert len(set(keys)) == 1, f"{filename} produced mismatched keys across workers: {keys}"
        assert len(keys[0]) == 50
        assert not list(pkg_dir.glob(".secret_key.*.tmp"))
