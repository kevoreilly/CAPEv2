# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.views.decorators.http import require_safe

from lib.cuckoo.core.data.tasking import TasksMixIn

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database
from lib.cuckoo.core.data.task import TASK_COMPLETED, TASK_REPORTED
try:
    import users.tenancy as _ut
except ImportError:  # MT layer not deployed -> dashboard degrades to the single "global" view
    _ut = None


# Conditional decorator for web authentication
class conditional_login_required:
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition

    def __call__(self, func):
        if settings.ANON_VIEW:
            return func
        if not self.condition:
            return func
        return self.decorator(func)


def format_number_with_space(number):
    return f"{number:,}".replace(",", " ")


def entitled_scopes(user):
    """Return the list of scope keys this user is entitled to see.

    When multitenancy is disabled or the user is a local-admin (break-glass),
    returns ["global"] — the single panel that shows everything, preserving
    legacy behaviour.  Otherwise returns the per-scope panels appropriate for
    the viewer's tenancy.
    """
    if _ut is None:
        # _ut None can mean 'MT layer genuinely absent' (legacy single "global" panel) OR 'MT enabled but
        # the users.tenancy import chain broke' -- in the latter, ["global"] (see-all) would silently drop
        # the central enrichment scope to see-all. Fail CLOSED (no panels) when MT is detectably enabled,
        # mirroring the tenancy_optional facade (f3494f98) / viewer_scope (300fcb50).
        from lib.cuckoo.common.tenancy_optional import _mt_enabled

        return [] if _mt_enabled() else ["global"]
    v = _ut.viewer_for(user)
    cfg = _ut.multitenancy_config()
    # Mode-INDEPENDENT, mirroring can_read / viewer_scope_match: the scoped panels
    # apply in shared mode too (shared still hides other tenants' private/tenant
    # analyses; only PUBLIC is the shared pool). Only a disabled feature or a
    # break-glass local-admin collapses to the single see-all 'global' panel.
    if not cfg.enabled or v.is_local_admin:
        return ["global"]
    scopes = ["public"]
    if v.tenant_id is not None:
        scopes.append("tenant")
    if v.user_id is not None:   # anonymous/unauth has no "mine" — skip the empty panel
        scopes.append("mine")
    return scopes


_SCOPE_LABEL = {
    "public": "Public",
    "tenant": "My Tenant",
    "mine": "Mine",
    "global": "Global",
}


def entitled_scope_filter(user):
    """Combined mongo ``$match`` (over the report's ``info.*``) restricting results
    to the analyses ``user`` may read across all their entitled scopes. Returns
    ``None`` when no filter applies (global / break-glass / multitenancy disabled)
    so callers can leave their query unchanged, preserving the public install."""
    scopes = entitled_scopes(user)
    if "global" in scopes:
        return None
    if _ut is None:
        # MT enabled but users.tenancy broke (entitled_scopes returned [] via _mt_enabled) -> no _ut to
        # resolve a scope; fail closed to a deny-all $match rather than crash on _ut.viewer_for or see-all.
        return {"info.id": -1}
    from lib.cuckoo.common.tenancy import scope_match

    v = _ut.viewer_for(user)
    clauses = []
    for s in scopes:
        sm = scope_match(s, v)
        if sm is not None:
            clauses.append(sm)
    # No entitled scope resolved (e.g. tenant-less, unauth) -> match nothing.
    return {"$or": clauses} if clauses else {"info.id": -1}


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request):
    db: TasksMixIn = Database()
    v = _ut.viewer_for(request.user) if _ut is not None else None

    scopes = entitled_scopes(request.user)
    # Single global panel (multitenancy disabled / break-glass local-admin) must be
    # byte-for-byte identical to upstream: build the legacy "report" dict, which is
    # left empty ({}) unless there are completed/reported tasks, and let the template
    # collapse the per-scope chrome. Only the genuinely-multi-panel (MT-on scoped)
    # case gets the per-scope labelled layout.
    single_global = scopes == ["global"]

    panels = []
    for scope in scopes:
        states = db.get_tasks_status_count(scope=scope, viewer=v)
        total_tasks = db.count_tasks(scope=scope, viewer=v) or 0
        total_samples = db.count_samples(scope=scope, viewer=v) or 0

        # For the following stats we're only interested in completed tasks.
        tasks_done = states.get(TASK_COMPLETED, 0) + states.get(TASK_REPORTED, 0)

        if single_global:
            # Upstream: report stays {} unless there are completed/reported tasks.
            report = {}
            if tasks_done:
                # Get the time when the first task started and last one ended.
                started, completed = db.minmax_tasks(scope=scope, viewer=v)
                # It has happened that for unknown reasons completed and started were
                # equal in which case an exception is thrown, avoid this.
                if started and completed and int(completed - started):
                    hourly = 60 * 60 * tasks_done / (completed - started)
                else:
                    hourly = 0
                report = dict(
                    total_samples=format_number_with_space(total_samples),
                    total_tasks=format_number_with_space(total_tasks),
                    states_count=states,
                    estimate_hour=format_number_with_space(int(hourly)),
                    estimate_day=format_number_with_space(int(24 * hourly)),
                )
            panels.append({"scope": scope, "label": _SCOPE_LABEL[scope], **report})
            continue

        # Estimate throughput for completed/reported tasks in this scope.
        estimate_hour = None
        estimate_day = None
        if tasks_done:
            started, completed = db.minmax_tasks(scope=scope, viewer=v)
            if started and completed and int(completed - started):
                hourly = 60 * 60 * tasks_done / (completed - started)
                estimate_hour = format_number_with_space(int(hourly))
                estimate_day = format_number_with_space(int(24 * hourly))

        panels.append({
            "scope": scope,
            "label": _SCOPE_LABEL[scope],
            "total_tasks": format_number_with_space(total_tasks),
            "total_samples": format_number_with_space(total_samples),
            "states_count": states,
            "estimate_hour": estimate_hour,
            "estimate_day": estimate_day,
        })

    data = {"title": "Dashboard", "panels": panels}
    return render(request, "dashboard/index.html", data)
