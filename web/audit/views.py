import json
import os
import sys
import logging
from typing import Optional, Dict

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseNotFound, HttpResponseForbidden
from django.shortcuts import redirect, render
from django import template
from django.template.loader import render_to_string
from django.views.decorators.http import require_POST
from django.urls import reverse

register = template.Library()

sys.path.append(settings.CUCKOO_PATH)

logger = logging.getLogger(__name__)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.audit_utils import TestLoader
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.data.audits import AuditsMixIn, TestSession
from lib.cuckoo.core.data.task import TASK_PENDING, Task
from lib.cuckoo.core.data.db_common import _utcnow_naive
from lib.cuckoo.core.data.audit_data import (TestRun, TEST_QUEUED, TEST_COMPLETE, TEST_FAILED, TEST_RUNNING, TEST_UNQUEUED)

'''
try:
    from django_ratelimit.decorators import ratelimit
except ImportError:
    try:
        from ratelimit.decorators import ratelimit
    except ImportError:
        print("missed dependency: poetry install")
'''

SESSIONS_PER_PAGE = 10
AUDIT_PACKAGES_ROOT = os.path.join(settings.CUCKOO_PATH, "tests", "audit_packages")
processing_cfg = Config("processing")
reporting_cfg = Config("reporting")
integrations_cfg = Config("integrations")
web_cfg = Config("web")
db: AuditsMixIn = Database()

anon_not_viewable_func_list = (
)

# Conditional decorator for web authentication
class conditional_login_required:
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition

    def __call__(self, func):
        if not hasattr(web_cfg, 'audit_framework') or \
            not hasattr(web_cfg.audit_framework, 'enabled') or \
            not web_cfg.audit_framework.enabled:
                def fail(*args, **kwargs):
                    return HttpResponseForbidden("Audit Framework is not set to enabled in web config.")
                return fail

        if settings.ANON_VIEW and func.__name__ not in anon_not_viewable_func_list:
            return func
        if not self.condition:
            return func
        return self.decorator(func)

@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def audit_index(request, page:int = 1):
    """
    The main index function for the /audit page with lists of sessions and tests
    Currently only handles paging for sessions as tests are probably better
    viewed as a single page while being picked through for a new session
    """
    with db.session.session_factory() as db_session, db_session.begin():
        available_tests = db.list_available_tests(db_session=db_session)
        for test in available_tests:
            # We create a new "virtual" attribute on the object
            if test.task_config:
                test.task_config_pretty = json.dumps(test.task_config, indent=2)
            else:
                test.task_config_pretty = "{}"

        paging = {}
        first_last_session = db.get_session_id_range()
        page = int(page)
        if page == 0:
            page = 1
        offset = (page - 1) * SESSIONS_PER_PAGE

        test_sessions = db.list_test_sessions(db_session=db_session, offset=offset, limit=SESSIONS_PER_PAGE)
        for audit_session in test_sessions:
            for run in audit_session.runs:
                if run.status not in [TEST_COMPLETE, TEST_FAILED]:
                    db.update_audit_tasks_status(db_session=db_session, audit_session=audit_session)
                    break
            audit_session.stats = get_session_stats(audit_session)

        paging["show_session_prev"] = "hide"
        paging["show_session_next"] = "hide"

        if test_sessions:
            if test_sessions[0].id != first_last_session[1]:
                paging["show_session_prev"] = "show"
            if test_sessions[-1].id != first_last_session[0]:
                paging["show_session_next"] = "show"

        sessions_count = db.count_test_sessions()
        pages_sessions_num = int(sessions_count / SESSIONS_PER_PAGE + 1)

        sessions_pages = []
        if pages_sessions_num < 11 or page < 6:
            sessions_pages = list(range(1, min(10, pages_sessions_num) + 1))
        elif page > 5:
            sessions_pages = list(range(min(page - 5, pages_sessions_num - 10) + 1, min(page + 5, pages_sessions_num) + 1))

        paging["sessions_page_range"] = sessions_pages
        paging["next_page"] = str(page + 1)
        paging["prev_page"] = str(page - 1)
        paging["current_page"] = page

        return render(
            request,
            "audit/index.html",
            {
                "available_tests": available_tests,
                "total_sessions": sessions_count,
                "sessions": test_sessions,
                "paging": paging,
            },
        )


@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def create_test_session(request):
    """
    Takes a list of test IDs in the test_ids POST value and generates
    a new audit session from them.
    Redirects to the new session on success.
    Redirects back to the session list on failure.
    """
    if request.method != "POST":
        return redirect("audit_index")

    test_ids = request.POST.getlist("test_ids")
    if not test_ids:
        messages.warning(request, "No tests were selected.")
        return redirect("audit_index")

    try:
        # This calls the SQLAlchemy logic we discussed to create the TestSession + TestRuns
        session_id = db.create_session_from_tests(test_ids)

        # Success! Now we go to the "Mission Control" page
        return redirect("test_session", session_id=session_id)

    except Exception as e:
        messages.error(request, "Error creating session: %s",str(e))
        return redirect("audit_index")


@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def reload_available_tests(request):
    """
    Triggers the TestLoader to refresh the AvailableTests table.
    By default reads from tests/audit_packages
    """
    # Path where your test subdirectories live
    if not os.path.isdir(AUDIT_PACKAGES_ROOT):
        errmsg = "reload_available_tests::Audit packages root is not an existing directory: " + AUDIT_PACKAGES_ROOT
        messages.error(request, errmsg)
        return redirect(reverse("audit_index") + "#available-tests")

    loader = TestLoader(AUDIT_PACKAGES_ROOT)
    result = loader.load_tests()
    logger.info("Test load results: %s", json.dumps(result))

    try:
        # This calls the method you added to your Mixin
        count = db.reload_tests(result["available"], result["unavailable"])
        if result["unavailable"]:
            if not result["available"]:
                errmg = "Failed to load %d tests from %s [%s]."%\
                    (len(result["unavailable"]),
                     AUDIT_PACKAGES_ROOT,
                     str(result['unavailable']))
                messages.error(request,errmg)
            else:
                messages.warning(
                    request,
                    f"Partial failure to reload tests from {AUDIT_PACKAGES_ROOT} [Failed: {result['unavailable']}].",
                )
        else:
            messages.success(request, f"Successfully reloaded all {count} tests from {AUDIT_PACKAGES_ROOT}")

    except Exception as e:
        messages.error(request, f"reload_available_tests:: Error reloading tests: {str(e)}")
        logger.exception("reload_available_tests::exception")

    return redirect(reverse("audit_index") + "#available-tests")


@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def delete_test_session(request, session_id: int):
    """
    Purges a tests session and its task storage directory
    Fails if any of the tests are active
    """
    try:
        session = db.get_test_session(session_id)
        if session:
            if not db.delete_test_session(session_id):
                messages.warning(request, f"Could not delete active session #{session_id}.")
    except Exception as e:
        messages.error(request, f"Error deleting session: {str(e)}")
        logger.error("Error deleting session: %s",str(e))
    return redirect("audit_index")


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def session_index(request, session_id: int):
    """
    The index function for an invididual audit session
    """
    session_data = db.get_test_session(session_id)
    stats = get_session_stats(session_data)

    if not session_data:
        messages.warning(request, "Session not found.")
        return redirect("audit_index")

    run_html = {}
    for run in session_data.runs:
        run_status = _render_run_update(request, session_id, run.id)
        run_html[run.id] = run_status["html"]

    return render(
        request,
        "audit/session.html",
        {"session": session_data, "runs": session_data.runs, "run_html": run_html, "stats": stats},
    )


def generate_task_diagnostics(task: Task, test_run: TestRun):
    """
    Gathers CAPE task timestamps
    """
    diagnostics = {}
    timenow = _utcnow_naive()
    if task.added_on:
        if task.started_on:
            diagnostics["start_wait"] = task.started_on - task.added_on
        else:
            diagnostics["start_wait"] = timenow - task.added_on

        if task.started_on:
            if task.completed_on:
                diagnostics["run_time"] = task.completed_on - task.started_on
            else:
                diagnostics["run_time"] = timenow - task.started_on

        if task.completed_on:
            if task.reporting_finished_on:
                diagnostics["report_wait"] = task.reporting_finished_on - task.completed_on
            else:
                # implementing reporting_finished_on was a recent change, it may not be there
                if test_run.status == TEST_RUNNING:
                    diagnostics["report_wait"] = timenow - task.completed_on

    return diagnostics

def _format_json_config(config_raw):
    return json.dumps(config_raw, indent=2)

def _render_run_update(request, session_id: int, testrun_id: int):
    """
    The mechanics of rendering sessions is here
    This framework is currently lazy loaded, so test sessions will be updated
    and objectives evaluated when this is called, making it potentially slow on
    some occasions.
    """
    db_test_session = db.get_test_session(session_id)
    test_run = next((r for r in db_test_session.runs if r.id == testrun_id), None)
    cape_task_info = None
    diagnostics = None
    if test_run.cape_task_id is not None:
        cape_task_info = db.view_task(test_run.cape_task_id)
        if cape_task_info:
            diagnostics = generate_task_diagnostics(cape_task_info, test_run)

    if test_run.test_definition.task_config:
        test_run.task_config_pretty = _format_json_config(test_run.test_definition.task_config)

    # Render just the partial file with the updated 'run' object
    html = render_to_string(
        "audit/partials/session_test_run.html",
        {"run": test_run, "cape_task": cape_task_info, "diagnostics": diagnostics},
        request=request,
    )
    return {"html": html, "status": test_run.status, "id": test_run.id}


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def get_run_update(request, session_id: int, testrun_id: int):
    """
    Get an update for a test run of a session without having to reload the whole page
    """
    return JsonResponse(_render_run_update(request, session_id, testrun_id))

def get_session_stats(db_test_session: TestSession) -> Optional[Dict]:
    """
    Fetch test and objective statistics
    """
    if db_test_session is None:
        return None
    runs = db_test_session.runs
    stats = {
        "tests": { TEST_QUEUED: 0, TEST_UNQUEUED: 0, TEST_COMPLETE: 0, TEST_RUNNING: 0, TEST_FAILED: 0},
        "objectives": {"untested": 0, "skipped": 0, "success": 0, "failure": 0, "info": 0, "error": 0},
        "complete_but_unevaluated": 0,
    }
    for run in runs:
        stats["tests"][run.status] += 1
        for objective in run.objectives:
            stats["objectives"][objective.state] += 1
            if run.status == TEST_COMPLETE and objective.state == "untested":
                stats["complete_but_unevaluated"] += 1
    return stats


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)

@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def session_status(request, session_id: int):
    """
    The call used when a session page is being refreshed
    """
    db_test_session = db.get_test_session(session_id)
    if db_test_session is None:
        logger.warning("Tried to view session_status with invalid session %s", str(session_status))
        return HttpResponseNotFound

    runs = db_test_session.runs
    stats = get_session_stats(db_test_session)

    results = []
    for run in runs:
        results.append(_render_run_update(request, session_id, run.id))

    status_box = render_to_string(
        "audit/partials/session_status_header.html", {"stats": stats, "session": db_test_session}, request=request
    )

    return JsonResponse(
        {
            "test_cards": results,
            "status_box_card": status_box,
            "stats": stats,
            "count_unqueued": db_test_session.queued_run_count,
            "count_queued": db_test_session.unqueued_run_count,
        }
    )


def inner_queue_test(request, session_id: int, testrun_id: int) -> Optional[int]:
    """
    Queue a test from an audit session as a CAPE task
    Returns the cape task id if success, or None if failure
    """
    user_id = request.user.id or 0
    cape_task_id = None
    try:
        cape_task_id = db.queue_audit_test(session_id, testrun_id, user_id)
        db.assign_cape_task_to_testrun(testrun_id, cape_task_id)
        logger.info("CAPE queued task %d to service audit [session:%d test:%d user:%d]",
                    cape_task_id, session_id, testrun_id, user_id)
        return cape_task_id
    except Exception as ex:
        messages.error(request, f"Task Exception: {ex}")
    return None


@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def queue_test(request, session_id: int, testrun_id: int):
    """
    Path to queue a single test of a session
    """
    cape_task_id = inner_queue_test(request, session_id, testrun_id)
    if cape_task_id:
        return JsonResponse({"status": "success", "message": "Test queued successfully", "task_id": cape_task_id})
    else:
        return JsonResponse({"status": "failure", "message": "Could not queue test - see messages.", "task_id": None})

@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def queue_all_tests(request, session_id: int):
    """
    Path to queue all unqueued tests of a session
    Returns the test_run_id -> task_id mapping
    """
    task_ids = []
    db_test_session = db.get_test_session(session_id)
    for run in db_test_session.runs:
        if run.status != TEST_UNQUEUED:
            continue
        task_id = inner_queue_test(request, session_id, run.id)
        if task_id is not None:
            task_ids.append({"run": run.id, "task": task_id})
    return JsonResponse({"task_ids": task_ids})

def inner_unqueue_test(testrun: TestRun) -> Optional[int]:
    """
    Try to delete a CAPE task of a session which has been queued (but not started yet)
    @parameter testrun: The TestRun db object of the run to clear
    Returns the deleted CAPE task id, or None if failed
    """
    # note: I tried to use db.delete_tasks(), with the task_id's & TASK_PENDING
    # filter but couldn't get round commit/transaction errors
    # there is a chance of some race conditions here
    if testrun.cape_task_id is not None and testrun.status == TEST_QUEUED:
        task_id = testrun.cape_task_id
        cape_task = db.view_task(task_id)
        if cape_task.status == TASK_PENDING:
            db.delete_task(task_id)
            testrun.status = TEST_UNQUEUED
            testrun.cape_task_id = None
            return task_id
    return None

@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def unqueue_test(request, session_id, testrun_id):
    """
    Path to unqueue a single test of a session
    """
    run = db.get_audit_session_test(session_id, testrun_id)
    if not run:
        return JsonResponse({"status": "failure", "message": "Could not retrieve test task", "task_id": None})

    cape_task_id = inner_unqueue_test(run)
    if cape_task_id:
        return JsonResponse({"status": "success", "message": "Test unqueued successfully", "task_id": cape_task_id})
    else:
        return JsonResponse({"status": "failure", "message": "Could not unqueue test", "task_id": None})

@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def unqueue_all_tests(request, session_id: int):
    deleted_task_ids = []
    db_test_session = db.get_test_session(session_id)
    if not db_test_session:
        logger.warning("Request to unqueue all tests of invalid session %d",session_id)
    else:
        for run in db_test_session.runs:
            task_id = inner_unqueue_test(run)
            if task_id:
                deleted_task_ids.append(task_id)
    return JsonResponse({"deleted_tasks": deleted_task_ids})


@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def update_task_config(request, availabletest_id):
    if request.method == "POST":
        with db.session.session_factory() as db_session, db_session.begin():
            test = db.get_test(availabletest_id=availabletest_id, db_session=db_session)
            raw_json = request.POST.get("task_config", "").strip()

            try:
                # 1. Validate JSON syntax
                parsed_data = json.loads(raw_json)

                # 2. Save the minified version to the DB (or keep pretty if preferred)
                test.task_config = parsed_data
                db_session.commit()
                messages.success(request, f"Configuration for Test {test.name} (#{test.id}) updated successfully.")
                return JsonResponse({"success": True, "config_pretty": _format_json_config(parsed_data)})

            except json.JSONDecodeError as e:
                messages.error(request, f"Failed to save: Invalid JSON format. Error: {str(e)}")
                return JsonResponse({"success": False, "error": "bad json: "+str(e)})

            except Exception as e:
                messages.error(request, f"An unexpected error occurred: {str(e)}")
                return JsonResponse({"success": False, "error": str(e)})
