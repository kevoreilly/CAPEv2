"""MT-absent integration smoke — the inverse of the MT-present faithful suite.

With the multi-tenant layer (users.tenancy + lib.cuckoo.common.tenancy) made unimportable,
the import-optional facades must fall back to see-all AND the base view modules must still
import. This proves central mode runs WITHOUT our multi-tenant fork (the Phase 4 un-weave
goal). Box-run: needs the Django/CAPE environment (pytest-django sets up Django). The test
restores the real facade bindings in a finally so it doesn't pollute later tests.
"""
import builtins
import importlib


def test_mt_absent_facades_see_all_and_base_views_import():
    import lib.cuckoo.common.tenancy_optional as L
    import web.tenancy_optional as W

    real_import = builtins.__import__

    def hide(name, *args, **kwargs):
        if name in ("users.tenancy", "lib.cuckoo.common.tenancy") or \
           name.startswith("users.tenancy.") or name.startswith("lib.cuckoo.common.tenancy."):
            raise ImportError("simulated: MT layer absent")
        return real_import(name, *args, **kwargs)

    builtins.__import__ = hide
    try:
        # re-run the facades' module-level (constant) imports under the hidden layer
        importlib.reload(L)
        importlib.reload(W)

        # lib facade -> MT-disabled-equivalent fallbacks
        assert L.multitenancy_config().enabled is False
        assert L.viewer_for(object()).is_local_admin is True
        assert L.PUBLIC == "public" and L.VISIBILITIES == ("public", "tenant", "private")
        assert L.scope_match("public", object()) is None
        assert L.viewer_scope_match(object()) is None

        # web facade -> see-all fallbacks (can_* True, scopes None)
        assert W.can_view_task(object(), object()) is True
        assert W.can_view_sample(object(), sha256="x") is True
        assert W.viewer_for(object()).is_local_admin is True
        assert W.viewer_scope_filter(object()) is None
        assert W.submission_scope(object()) == (None, W.PUBLIC)  # 2-tuple, not None (callers unpack)

        # the base view modules import with the MT layer absent (the core un-weave claim)
        for mod in ("analysis.views", "apiv2.views", "submission.views",
                    "dashboard.views", "guac.views", "guac.consumers", "compare.views"):
            importlib.import_module(mod)
    finally:
        builtins.__import__ = real_import
        importlib.reload(L)  # restore real bindings for any later tests in the session
        importlib.reload(W)


def test_no_unguarded_mt_app_imports_in_gate_sites():
    """Regression guard for the class the module-import smoke above MISSES: a raw, unguarded
    `from users.tenancy import ...` in a FUNCTION-LOCAL import (fires only at call time) crashes a
    single-node/upstream build where the `users` MT app is absent. The MT app must be reached ONLY
    through the import-optional facades (tenancy_optional) or a local try/except ImportError.
    Whitelist = the two facades + central_scope's guarded fallback."""
    import os
    import re

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    allowed = {
        "web/web/tenancy_optional.py",
        "lib/cuckoo/common/tenancy_optional.py",
        "web/analysis/central_scope.py",  # raw import is inside try/except ImportError (guarded)
    }
    offenders = []
    for sub in ("lib", "web", "modules", "utils"):
        for dirpath, _dirs, files in os.walk(os.path.join(root, sub)):
            for fn in files:
                if not fn.endswith(".py"):
                    continue
                rel = os.path.relpath(os.path.join(dirpath, fn), root)
                if rel in allowed or "test" in rel or rel.endswith("conftest.py"):
                    continue
                try:
                    src = open(os.path.join(dirpath, fn), encoding="utf-8").read()
                except OSError:
                    continue
                if re.search(r"^\s*from users\.tenancy import", src, re.M):
                    offenders.append(rel)
    assert not offenders, f"unguarded MT-app imports (route through the tenancy_optional facade): {offenders}"
