import datetime
import http
import json
import os
import sys
import logging

from typing import Optional
from contextlib import suppress
from io import BytesIO
from pathlib import Path
from urllib.parse import quote
from wsgiref.util import FileWrapper

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import BadRequest, PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect, StreamingHttpResponse, JsonResponse, HttpResponseNotFound
from django.shortcuts import redirect, render
from django import template
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_safe
from django.urls import reverse
from rest_framework.decorators import api_view

register = template.Library()

sys.path.append(settings.CUCKOO_PATH)

logger = logging.getLogger(__name__)

from lib.cuckoo.common.pcap_utils import PcapToNg
import modules.processing.network as network
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import ANALYSIS_BASE_PATH, CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists, path_get_size, path_mkdir, path_read_file, path_safe
from lib.cuckoo.common.utils import delete_folder, yara_detected
from lib.cuckoo.common.web_utils import category_all_files, my_rate_minutes, my_rate_seconds, perform_search, rateblock, statistics
from lib.cuckoo.common.test_harness_utils import TestLoader
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.data.audits import AuditsMixIn
from lib.cuckoo.core.data.task import TASK_PENDING, Task
from lib.cuckoo.core.data.db_common import _utcnow_naive
from modules.reporting.report_doc import CHUNK_CALL_SIZE

try:
    from django_ratelimit.decorators import ratelimit
except ImportError:
    try:
        from ratelimit.decorators import ratelimit
    except ImportError:
        print("missed dependency: poetry install")

from lib.cuckoo.common.webadmin_utils import disable_user

try:
    import re2 as re
except ImportError:
    import re

try:
    import requests

    HAVE_REQUEST = True
except ImportError:
    HAVE_REQUEST = False

try:
    import pyzipper

    HAVE_PYZIPPER = True
except ImportError:
    print("Missed dependency: poetry install")
    HAVE_PYZIPPER = False

SESSIONS_PER_PAGE = 10

processing_cfg = Config("processing")
reporting_cfg = Config("reporting")
integrations_cfg = Config("integrations")
web_cfg = Config("web")
db: AuditsMixIn = Database()

# Used for displaying enabled config options in Django UI
enabledconf = {}
on_demand_conf = {}
for cfile in ("integrations", "reporting", "processing", "auxiliary", "web", "distributed"):
    curconf = Config(cfile)
    confdata = curconf.get_config()
    for item in confdata:
        if "enabled" in confdata[item]:
            if confdata[item]["enabled"] == "yes":
                enabledconf[item] = True
                if confdata[item].get("on_demand", "no") == "yes":
                    on_demand_conf[item] = True
            else:
                enabledconf[item] = False

if enabledconf["mongodb"]:
    from bson.objectid import ObjectId

    from dev_utils.mongodb import mongo_aggregate, mongo_delete_data, mongo_find, mongo_find_one, mongo_update_one

es_as_db = False
essearch = False
if enabledconf["elasticsearchdb"]:
    from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index, get_calls_index, get_query_by_info_id

    essearch = Config("reporting").elasticsearchdb.searchonly
    if not essearch:
        es_as_db = True

    es = elastic_handler

DISABLED_WEB = True
# if elif else won't work here
if enabledconf["mongodb"] or enabledconf["elasticsearchdb"]:
    DISABLED_WEB = False


anon_not_viewable_func_list = (
    "file",
    "remove",
    # "search",
    "pending",
    "filtered_chunk",
    "search_behavior",
    "statistics_data",
)


# Conditional decorator for web authentication
class conditional_login_required:
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition

    def __call__(self, func):
        if settings.ANON_VIEW and func.__name__ not in anon_not_viewable_func_list:
            return func
        if not self.condition:
            return func
        return self.decorator(func)


def _path_safe(path: str) -> bool:
    if web_cfg.security.check_path_safe:
        return path_safe(path)

    return True


@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def create_test_session(request):
    if request.method != "POST":
        return redirect("test_harness")

    test_ids = request.POST.getlist("test_ids")

    if not test_ids:
        messages.warning(request, "No tests were selected.")
        return redirect("test_harness")

    try:
        # This calls the SQLAlchemy logic we discussed to create the TestSession + TestRuns
        session_id = db.create_session_from_tests(test_ids)

        # Success! Now we go to the "Mission Control" page
        return redirect("test_session", session_id=session_id)

    except Exception as e:
        messages.error(request, f"Error creating session: {str(e)}")
        return redirect("test_harness")


@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def reload_available_tests(request):
    logger.info("Reloading test harness tests via web interface")
    """Triggers the TestLoader to refresh the AvailableTests table."""

    # Path where your test subdirectories live
    tests_root = os.path.join(settings.CUCKOO_PATH, "tests/dynamic_test_harness")
    loader = TestLoader(tests_root)
    result = loader.load_tests()
    logger.info("Test load results: %s", json.dumps(result))

    try:
        # This calls the method you added to your Mixin
        count = db.reload_tests(result["available"], result["unavailable"])
        if result["unavailable"]:
            messages.warning(
                request,
                f"Partially reloaded {count} tests from {tests_root} [Avail:{result['available']}, Unavail: {result['unavailable']}].",
            )
        else:
            messages.success(request, f"Successfully reloaded all {count} tests from {tests_root} {result['available']}.")

    except Exception as e:
        messages.error(request, f"reload_available_tests:: Error reloading tests: {str(e)}")

    return redirect(reverse("test_harness") + "#available-tests")


def test_harness_index(request, page=1):
    # Fetch your tests from the DB
    available_tests = db.list_available_tests()  # or however you fetch them

    # Attach a pretty-printed string version of the config to each test object
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
    
    test_sessions = db.list_test_sessions(offset=offset, limit=SESSIONS_PER_PAGE)
    
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

    return render(request, 
                  "test_harness/index.html", 
                  { "available_tests": available_tests, 
                    "sessions": test_sessions,
                    "paging": paging})


@require_POST
def delete_test_session(request, session_id):
    try:
        session = db.get_test_session(session_id)
        if session:
            if not db.delete_test_session(session_id):
                messages.warning(request, f"Could not delete active session #{session_id}.")
    except Exception as e:
        messages.error(request, f"Error deleting session: {str(e)}")
        logger.error(f"Error deleting session: {str(e)}")

    return redirect("test_harness")


def session_index(request, session_id):
    # Fetch the session and join the runs and test metadata in one go
    session_data = db.get_test_session(session_id)
    stats = get_session_stats(session_data)

    if not session_data:
        messages.warning(request, "Session not found.")
        return redirect("test_harness")

    cape_tasks = {}
    run_html = {}
    for run in session_data.runs:
        run_status = _render_run_update(request, session_id, run.id)
        run_html[run.id] = run_status["html"]

    return render(
        request,
        "test_harness/session.html",
        {"session": session_data, "runs": session_data.runs, "run_html": run_html, "stats": stats},
    )

def generate_task_diagnostics(task, test_run):
    diagnostics = {}
    timenow = _utcnow_naive()
    if task.added_on:
        if task.started_on:
            diagnostics['start_wait'] = task.started_on - task.added_on
        else:
            diagnostics['start_wait'] = timenow - task.added_on

        if task.started_on:
            if task.completed_on:
                diagnostics['run_time'] = task.completed_on - task.started_on
            else:
                diagnostics['run_time'] = timenow - task.started_on
                
        if task.completed_on:
            if task.reporting_finished_on:
                diagnostics['report_wait'] = task.reporting_finished_on - task.completed_on
            else:
                # implementing reporting_finished_on was a recent change, it may not be there
                if test_run.status == "running":
                    diagnostics['report_wait'] = timenow - task.completed_on
    
    return diagnostics


def _render_run_update(request, session_id, testrun_id):
    db_test_session = db.get_test_session(session_id)
    test_run = next((r for r in db_test_session.runs if r.id == testrun_id), None)
    cape_task_info = None
    diagnostics = None
    if test_run.cape_task_id != None:
        cape_task_info = db.view_task(test_run.cape_task_id)        
        if cape_task_info:
            diagnostics = generate_task_diagnostics(cape_task_info, test_run)

    if test_run.test_definition.task_config:
        test_run.task_config_pretty = json.dumps(test_run.test_definition.task_config, indent=2)

    # Render just the partial file with the updated 'run' object
    html = render_to_string(
        "test_harness/partials/session_test_run.html", {"run": test_run, "cape_task": cape_task_info, "diagnostics": diagnostics}, request=request
    )
    return {"html": html, "status": test_run.status, "id": test_run.id}


def get_run_update(request, session_id, testrun_id):
    return JsonResponse(_render_run_update(request, session_id, testrun_id))


def get_session_stats(db_test_session):
    if db_test_session is None:
        return None

    runs = db_test_session.runs
    results = []
    stats = {
        "tests": {
            "queued": 0,
            "unqueued": 0,
            "complete": 0,
            "running": 0,
            "failed": 0,
        },
        "objectives": {"untested": 0, "skipped": 0, "success": 0, "failure": 0, "info": 0, "error": 0},
        "complete_but_unevaluated": 0,
    }
    for run in runs:
        stats["tests"][run.status] += 1
        for objective in run.objectives:
            stats["objectives"][objective.state] += 1
            if run.status == "complete" and objective.state == "untested":
                stats["complete_but_unevaluated"] += 1

    return stats


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def session_status(request, session_id):
    db_test_session = db.get_test_session(session_id)
    if db_test_session is None:
        logger.warning("Tried to view session_status with in valid session %s", str(session_status))
        return HttpResponseNotFound

    runs = db_test_session.runs
    stats = get_session_stats(db_test_session)

    results = []
    for run in runs:
        results.append(_render_run_update(request, session_id, run.id))

    status_box = render_to_string(
        "test_harness/partials/session_status_header.html", {"stats": stats, "session": db_test_session}, request=request
    )

    return JsonResponse(
        {
            "test_cards": results,
            "status_box_card": status_box,
            "stats": stats,
            "count_unqueued": db_test_session.queued_run_count,
            "count_queued": db_test_session.unqueued_run_count,
            # Optional: update the top buttons too
        }
    )

def inner_queue_test(request, session_id, testrun_id) -> Optional[int]:
    user_id = request.user.id or 0
    cape_task_id = None
    try:
        cape_task_id = db.queue_audit_test(session_id, testrun_id, user_id)
        db.assign_cape_task_to_testrun(testrun_id, cape_task_id)
        messages.success(request, f"Task added: id {cape_task_id}")
        return cape_task_id
    except Exception as ex:
        messages.error(request, f"Task Exception: {ex}")
    return None

@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def queue_test(request, session_id, testrun_id):
    cape_task_id = inner_queue_test(request, session_id, testrun_id)
    if cape_task_id:
        return JsonResponse({"status": "success", "message": "Test queued successfully", "task_id": cape_task_id})
    else:
        return JsonResponse({"status": "failure", "message": "Could not queue test", "task_id": None})


@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def queue_all_tests(request, session_id):
    task_ids = []
    db_test_session = db.get_test_session(session_id)
    for run in db_test_session.runs:
        task_id = inner_queue_test(request, session_id, run.id)
        if task_id != None:
            task_ids.append({'run':run.id, 'task':task_id})
    return JsonResponse({"task_ids": task_ids})

@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def unqueue_all_tests(request, session_id):    
    
    # note: I tried to use db.delete_tasks(), with the task_id's & TASK_PENDING
    # filter but couldn't get round commit/transaction errors
    # there is a chance of some race conditions here
    db_test_session = db.get_test_session(session_id)
    deleted_task_ids = []
    if db_test_session:
        for run in db_test_session.runs:
            if run.cape_task_id != None and run.status == "queued":
                cape_task = db.view_task(run.cape_task_id)
                if cape_task.status == TASK_PENDING:
                    db.delete_task(run.cape_task_id)
                    deleted_task_ids.append(run.cape_task_id)
                    run.status = "unqueued"
                    run.cape_task_id = None

    return JsonResponse({'deleted_tasks': len(deleted_task_ids)})