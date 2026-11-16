import os
import subprocess
import sys
from pathlib import Path

from allauth.account.checks import adapter_check, settings_check
from allauth.account.forms import LoginForm
from django.conf import settings
from django.test import override_settings

DEPRECATED_ALLAUTH_SETTINGS = (
    "ACCOUNT_EMAIL_REQUIRED",
    "ACCOUNT_USERNAME_REQUIRED",
    "ACCOUNT_AUTHENTICATION_METHOD",
    "ACCOUNT_SIGNUP_EMAIL_ENTER_TWICE",
    "ACCOUNT_SIGNUP_PASSWORD_ENTER_TWICE",
)


def test_web_settings_uses_modern_allauth_settings():
    assert settings.ACCOUNT_LOGIN_METHODS == {"username"}
    assert "username*" in settings.ACCOUNT_SIGNUP_FIELDS
    assert "password1*" in settings.ACCOUNT_SIGNUP_FIELDS
    assert "password2*" in settings.ACCOUNT_SIGNUP_FIELDS
    assert any(field in settings.ACCOUNT_SIGNUP_FIELDS for field in ("email", "email*"))

    for deprecated_name in DEPRECATED_ALLAUTH_SETTINGS:
        assert not hasattr(settings, deprecated_name), f"Deprecated setting {deprecated_name} must not be defined"


def test_allauth_checks_pass_with_default_settings():
    assert settings_check(None) == []
    assert adapter_check(None) == []


@override_settings(
    ACCOUNT_EMAIL_VERIFICATION="none",
    ACCOUNT_SIGNUP_FIELDS=["username*", "email", "password1*", "password2*"],
)
def test_allauth_checks_pass_when_email_optional_and_verification_disabled():
    assert settings_check(None) == []
    assert adapter_check(None) == []


@override_settings(
    ACCOUNT_LOGIN_METHODS={"username", "email"},
    ACCOUNT_UNIQUE_EMAIL=True,
    ACCOUNT_SIGNUP_FIELDS=["email*", "password1*", "password2*"],
)
def test_allauth_checks_pass_and_login_form_has_password_for_email_login():
    assert settings_check(None) == []
    assert adapter_check(None) == []
    assert "password" in LoginForm().fields


def test_mandatory_email_verification_requires_email_signup_field(tmp_path):
    """When email_required is disabled but email_confirmation is enabled, email* must be derived."""
    repo_root = Path(__file__).resolve().parents[2]
    web_dir = repo_root / "web"

    custom_dir = tmp_path / "isolated_custom" / "conf"
    custom_dir.mkdir(parents=True, exist_ok=True)
    override_dir = tmp_path / "override"
    override_dir.mkdir(exist_ok=True)
    (override_dir / "web.conf").write_text(
        "[registration]\nemail_required = no\nemail_confirmation = yes\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    for key in ("https_proxy", "http_proxy", "no_proxy", "ftp_proxy", "all_proxy"):
        env.pop(key, None)
    env["CAPE_DISABLE_ROOT_CONFIGS"] = "1"
    env["CAPE_CD"] = str(override_dir)
    env["DJANGO_SETTINGS_MODULE"] = "web.settings"
    env["PYTHONPATH"] = f"{web_dir}:{repo_root}"

    code = (
        "import lib.cuckoo.common.config as cfg_mod; "
        f"cfg_mod.CUSTOM_CONF_DIR = {str(custom_dir)!r}; "
        "import django; django.setup(); "
        "from django.conf import settings; "
        "import web.settings as web_settings; "
        "from allauth.account.checks import adapter_check, settings_check; "
        "assert settings.ACCOUNT_EMAIL_VERIFICATION == 'mandatory'; "
        "assert web_settings._email_signup_field == 'email*'; "
        "assert settings.ACCOUNT_SIGNUP_FIELDS == ['username*', 'email*', 'password1*', 'password2*']; "
        "assert settings_check(None) == []; "
        "assert adapter_check(None) == []"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(web_dir),
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
