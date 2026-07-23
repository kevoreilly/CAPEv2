import os
import re


def test_guac_settings_defines_every_setting_the_guac_app_references():
    """guac-web loads web.guac_settings (web/asgi.py sets DJANGO_SETTINGS_MODULE=web.guac_settings),
    NOT web.settings. So any custom `settings.X` the guac app references at import time MUST be
    defined in guac_settings.py — otherwise `import guac.urls` raises AttributeError and EVERY
    /guac/ request 500s (browser: "Connection error"), silently killing the interactive live-VM
    Guacamole tunnel. That failure mode is invisible to the apiv2 coverage gate, which imports
    guac.views under web.settings (where the setting IS defined).

    Static scan (no import — guac_settings runs heavy DB init at import). Django built-ins
    (DEBUG, STATIC_URL, ...) are also asserted, which is fine: guac_settings defines the ones it
    uses; the real target is custom CAPE settings like WEB_AUTHENTICATION.
    """
    guac_dir = os.path.dirname(os.path.abspath(__file__))
    guac_settings = os.path.normpath(os.path.join(guac_dir, "..", "web", "guac_settings.py"))
    referenced = set()
    for fn in sorted(os.listdir(guac_dir)):
        if fn.endswith(".py") and not fn.startswith("test"):
            src = open(os.path.join(guac_dir, fn)).read()
            referenced |= set(re.findall(r"\bsettings\.([A-Z_][A-Z0-9_]+)", src))
    gs = open(guac_settings).read()
    missing = [s for s in sorted(referenced) if not re.search(r"^\s*%s\s*=" % re.escape(s), gs, re.M)]
    assert not missing, "web.guac_settings is missing settings the guac app references: %s" % missing
