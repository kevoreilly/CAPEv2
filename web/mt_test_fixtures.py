import pytest

from lib.cuckoo.core.database import init_database, reset_database_FOR_TESTING_ONLY


@pytest.fixture
def mt_enabled(monkeypatch):
    """Force multitenancy ON for isolation tests. With the feature disabled
    (the default), viewer_for short-circuits to see-all (legacy behavior), so
    denial assertions only hold when it's enabled."""
    from lib.cuckoo.common.tenancy import MTConfig
    import users.tenancy as ut

    monkeypatch.setattr(
        ut, "multitenancy_config",
        lambda: MTConfig(enabled=True, mode="locked", default_visibility="",
                         local_admins_manage_all_tenants=True),
    )
    yield


@pytest.fixture
def mt_disabled(monkeypatch):
    """Force multitenancy OFF explicitly (the default) so MT-off invariant tests are
    robust to any ambient config: new MT gates must be true no-ops and views must fall
    through to upstream behavior byte-for-byte."""
    from lib.cuckoo.common.tenancy import MTConfig
    import users.tenancy as ut

    monkeypatch.setattr(
        ut, "multitenancy_config",
        lambda: MTConfig(enabled=False, mode="shared", default_visibility="",
                         local_admins_manage_all_tenants=True),
    )
    yield


@pytest.fixture
def cape_db():
    """Initialize the SQLAlchemy CAPE database (in-memory) for web-view tests
    that exercise the global `db` proxy (e.g. report/submit views). Named
    distinctly from `db` to avoid colliding with pytest-django's `db` fixture
    (which only sets up the Django DB, not CAPE's SQLAlchemy database)."""
    reset_database_FOR_TESTING_ONLY()
    try:
        init_database(dsn="sqlite://")
        yield
    finally:
        reset_database_FOR_TESTING_ONLY()
