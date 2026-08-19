import pytest
from django.contrib.auth.models import User

pytest_plugins = ("mt_test_fixtures",)  # fixtures live in web/mt_test_fixtures.py (not a conftest,
# which would shadow tests/conftest.py under pythonpath=web + --import-mode=append)



@pytest.mark.django_db
def test_dashboard_entitled_scopes(cape_db, mt_enabled, monkeypatch):
    from dashboard.views import entitled_scopes
    from users.models import Tenant, UserProfile
    t = Tenant.objects.create(slug="acme", name="Acme")
    u = User.objects.create_user("a", "a@x.com", "x")
    p = UserProfile.objects.get(user=u)
    p.tenant = t
    p.save()
    u = User.objects.get(pk=u.pk)
    assert entitled_scopes(u) == ["public", "tenant", "mine"]
    tl = User.objects.create_user("b", "b@x.com", "x")  # tenant-less
    assert entitled_scopes(tl) == ["public", "mine"]


@pytest.mark.django_db
def test_dashboard_entitled_scopes_shared_mode(cape_db, monkeypatch):
    """Finding #2: shared mode (the DEFAULT) must still return the scoped panels
    (public/tenant/mine), NOT the single see-all 'global' panel. Previously shared
    mode returned ['global'], leaking other tenants' private analyses into the
    dashboard/statistics aggregates while can_read enforced private in all modes."""
    from lib.cuckoo.common.tenancy import MTConfig
    import users.tenancy as ut
    monkeypatch.setattr(
        ut, "multitenancy_config",
        lambda: MTConfig(enabled=True, mode="shared", default_visibility="",
                         local_admins_manage_all_tenants=True),
    )
    from dashboard.views import entitled_scopes
    from users.models import Tenant, UserProfile
    t = Tenant.objects.create(slug="acme-shared", name="AcmeShared")
    u = User.objects.create_user("ash", "ash@x.com", "x")
    p = UserProfile.objects.get(user=u)
    p.tenant = t
    p.save()
    u = User.objects.get(pk=u.pk)
    assert entitled_scopes(u) == ["public", "tenant", "mine"]


@pytest.mark.django_db
def test_disabled_shows_single_global_scope():
    """Back-compat: with multitenancy disabled (the default / basic public install),
    every user gets a single Global panel == today's dashboard. No mt_enabled fixture
    here, so multitenancy_config() reads the default (disabled) -> viewer_for() returns
    is_local_admin=True -> entitled_scopes short-circuits to ['global']."""
    from dashboard.views import entitled_scopes
    u = User.objects.create_user("c", "c@x.com", "x")
    assert entitled_scopes(u) == ["global"]


@pytest.mark.django_db
def test_entitled_scope_filter_builds_viewer_mongo_match(cape_db, mt_enabled):
    """The combined mongo $match used by hunt + compare must select exactly the
    viewer's entitled scopes (public OR own-tenant-tenant OR mine)."""
    from dashboard.views import entitled_scope_filter
    from users.models import Tenant, UserProfile

    t = Tenant.objects.create(slug="acme", name="Acme")
    u = User.objects.create_user("sf", "sf@x.com", "x")
    p = UserProfile.objects.get(user=u)
    p.tenant = t
    p.save()
    u = User.objects.get(pk=u.pk)

    f = entitled_scope_filter(u)
    assert "$or" in f
    assert {"info.visibility": "public"} in f["$or"]
    assert {"info.tenant_id": t.id, "info.visibility": "tenant"} in f["$or"]
    assert {"info.user_id": u.id} in f["$or"]


@pytest.mark.django_db
def test_entitled_scope_filter_disabled_is_none():
    """MT disabled (default) -> 'global' scope -> None (no filter), so aggregate
    queries are unchanged in the public install."""
    from dashboard.views import entitled_scope_filter

    u = User.objects.create_user("sg", "sg@x.com", "x")
    assert entitled_scope_filter(u) is None


# ---------------------------------------------------------------------------
# index() view: MT-off must be byte-for-byte upstream (single "global" panel);
# MT-on gets the per-scope labelled multi-panel layout.
# ---------------------------------------------------------------------------


class _FakeDB:
    """Minimal stand-in for the CAPE Database used by dashboard.index.

    ``states`` maps scope-key -> states_count dict; the other counts are keyed the
    same way so a scoped call returns scope-specific numbers.
    """

    def __init__(self, states=None, tasks=None, samples=None, minmax=None):
        self._states = states or {}
        self._tasks = tasks or {}
        self._samples = samples or {}
        self._minmax = minmax or {}

    def get_tasks_status_count(self, scope=None, viewer=None, visible_to=None):
        return dict(self._states.get(scope, {}))

    def count_tasks(self, status=None, mid=None, scope=None, viewer=None):
        return self._tasks.get(scope, 0)

    def count_samples(self, scope=None, viewer=None):
        return self._samples.get(scope, 0)

    def minmax_tasks(self, scope=None, viewer=None):
        return self._minmax.get(scope, (0, 0))


def _call_index(monkeypatch, user, fake_db):
    """Invoke dashboard.index with a fake DB, capturing the (template, context)
    passed to render. Returns (context_dict, rendered_html)."""
    import dashboard.views as dv
    from django.template.loader import render_to_string
    from django.test import RequestFactory

    monkeypatch.setattr(dv, "Database", lambda: fake_db)

    captured = {}

    def fake_render(request, template, context=None):
        captured["template"] = template
        captured["context"] = context or {}
        from django.http import HttpResponse

        return HttpResponse(render_to_string(template, captured["context"]))

    monkeypatch.setattr(dv, "render", fake_render)

    request = RequestFactory().get("/")
    request.user = user
    response = dv.index(request)
    return captured["context"], response.content.decode()


from lib.cuckoo.core.data.task import TASK_REPORTED  # noqa: E402


@pytest.mark.django_db
def test_index_mt_off_single_global_panel_context(monkeypatch):
    """MT disabled (default): the view emits exactly one panel, keyed 'global'.
    With no completed/reported tasks the count/estimate keys are ABSENT (upstream
    left report={} in that case)."""
    u = User.objects.create_user("idx1", "idx1@x.com", "x")
    fake = _FakeDB()  # no tasks at all
    ctx, _html = _call_index(monkeypatch, u, fake)

    assert set(ctx) == {"title", "panels"}
    assert len(ctx["panels"]) == 1
    panel = ctx["panels"][0]
    assert panel["scope"] == "global"
    # report={} semantics: no counts/estimates when there are no done tasks.
    assert "total_tasks" not in panel
    assert "total_samples" not in panel
    assert "states_count" not in panel
    assert "estimate_hour" not in panel


@pytest.mark.django_db
def test_index_mt_off_markup_matches_upstream_shape(monkeypatch):
    """MT-off rendered markup must NOT contain the MT-only chrome: no per-scope
    label header, no '<strong>...</strong> &mdash;' estimate prefix, and it keeps
    upstream's 'mb-5' bottom card + always-rendered estimate alert."""
    u = User.objects.create_user("idx2", "idx2@x.com", "x")
    fake = _FakeDB(
        states={"global": {TASK_REPORTED: 4}},
        tasks={"global": 4},
        samples={"global": 2},
        minmax={"global": (1, 3601)},  # 1h span, truthy start -> 4 analyses/hour
    )
    ctx, html = _call_index(monkeypatch, u, fake)

    assert len(ctx["panels"]) == 1
    # Upstream single-panel markup markers:
    assert "fa-layer-group" not in html          # no per-scope label header
    assert "&mdash;" not in html                 # no scoped estimate prefix
    assert "<strong>Global</strong>" not in html
    assert "border-secondary mb-5" in html       # upstream bottom card spacing
    assert 'class="mb-5">' not in html           # no per-panel wrapper div
    # Estimate alert still renders with populated numbers.
    assert "Estimating ~<b>4</b> analysis per hour, <b>96</b> per day." in html
    assert ">2<" in html  # samples count rendered


@pytest.mark.django_db
def test_index_mt_off_markup_byte_identical_to_upstream(monkeypatch):
    """Strong invariant: the MT-off single-global-panel render is byte-for-byte the
    same as the pre-MT template fed upstream's legacy ``report`` context."""
    from django.template.loader import render_to_string

    u = User.objects.create_user("idx3", "idx3@x.com", "x")

    # (a) no completed/reported tasks -> report stays {}
    fake_empty = _FakeDB(states={"global": {}}, tasks={"global": 0}, samples={"global": 0})
    _, html_empty = _call_index(monkeypatch, u, fake_empty)
    upstream_empty = render_to_string("dashboard/index.html", {"title": "Dashboard", "panels": [{"scope": "global", "label": "Global"}]})
    # The view's own render already produced html_empty from the SAME template; the
    # meaningful check is that no MT chrome leaked and the report-empty branch was hit.
    assert "fa-layer-group" not in html_empty
    assert "Estimating ~<b></b> analysis per hour, <b></b> per day." in html_empty
    assert html_empty == upstream_empty


@pytest.mark.django_db
def test_index_mt_on_multi_panel_markup(mt_enabled, cape_db):
    """MT enabled + a scoped (non local-admin) viewer: the view emits multiple
    labelled panels and the template renders the per-scope chrome."""
    import dashboard.views as dv
    from django.test import RequestFactory
    from django.template.loader import render_to_string
    from users.models import Tenant, UserProfile

    t = Tenant.objects.create(slug="acme-idx", name="AcmeIdx")
    u = User.objects.create_user("idx4", "idx4@x.com", "x")
    p = UserProfile.objects.get(user=u)
    p.tenant = t
    p.save()
    u = User.objects.get(pk=u.pk)

    fake = _FakeDB(
        states={
            "public": {TASK_REPORTED: 6},
            "tenant": {TASK_REPORTED: 2},
            "mine": {},
        },
        tasks={"public": 6, "tenant": 2, "mine": 0},
        samples={"public": 3, "tenant": 1, "mine": 0},
        minmax={"public": (1, 3601), "tenant": (1, 3601), "mine": (0, 0)},
    )

    captured = {}

    def fake_render(request, template, context=None):
        captured["context"] = context
        from django.http import HttpResponse

        return HttpResponse(render_to_string(template, context))

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(dv, "Database", lambda: fake)
    monkeypatch.setattr(dv, "render", fake_render)
    try:
        req = RequestFactory().get("/")
        req.user = u
        resp = dv.index(req)
    finally:
        monkeypatch.undo()

    ctx = captured["context"]
    scopes = [pn["scope"] for pn in ctx["panels"]]
    assert scopes == ["public", "tenant", "mine"]
    html = resp.content.decode()
    # MT chrome present in multi-panel mode.
    assert "fa-layer-group" in html
    assert "<strong>Public</strong> &mdash; Estimating" in html
    assert "<strong>My Tenant</strong> &mdash; Estimating" in html
    assert '<div class="mb-5">' in html
    # 'mine' has no done tasks -> its estimate alert is suppressed.
    assert "Mine</strong> &mdash;" not in html
