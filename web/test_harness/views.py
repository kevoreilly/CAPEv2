# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import collections
import datetime
import json
import os
import subprocess
import sys
import tempfile
import zipfile
import logging

from contextlib import suppress
from io import BytesIO
from pathlib import Path
from urllib.parse import quote
from wsgiref.util import FileWrapper

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import BadRequest, PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect, StreamingHttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_safe
from django.urls import reverse
from rest_framework.decorators import api_view

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
from lib.cuckoo.core.data.task import TASK_PENDING, Task
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

TEST_LIMIT = 25

processing_cfg = Config("processing")
reporting_cfg = Config("reporting")
integrations_cfg = Config("integrations")
web_cfg = Config("web")

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

db = Database()

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

    test_ids = request.POST.getlist('test_ids')
    
    if not test_ids:
        messages.warning(request, "No tests were selected.")
        return redirect("test_harness")

    db = Database()
    try:
        # This calls the SQLAlchemy logic we discussed to create the TestSession + TestRuns
        session_id = db.create_session_from_tests(test_ids)
        
        # Success! Now we go to the "Mission Control" page
        return  redirect("test_session", session_id=session_id)
        
    except Exception as e:
        messages.error(request, f"Error creating session: {str(e)}")
        return redirect("test_harness")


@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def reload_available_tests(request):
    logger.info("Reloading test harness tests via web interface")
    """Triggers the TestLoader to refresh the AvailableTests table."""
    db = Database()
    # Path where your test subdirectories live
    tests_root = os.path.join(settings.CUCKOO_PATH, "tests/dynamic_test_harness") 
    loader = TestLoader(tests_root)
    result = loader.load_tests()
    logger.info("Test load results: %s",json.dumps(result))


    
    try:
        # This calls the method you added to your Mixin
        count = db.reload_tests(result['available'],result['unavailable'])
        messages.success(request, f"Successfully reloaded {count} tests.")
    except Exception as e:
        messages.error(request, f"reload_available_tests:: Error reloading tests: {str(e)}")
     
    return redirect(reverse('test_harness') + "#available-tests")


def test_harness_index(request):
    # Fetch your tests from the DB
    available_tests = db.list_available_tests() # or however you fetch them
    
    # Attach a pretty-printed string version of the config to each test object
    for test in available_tests:
        # We create a new "virtual" attribute on the object
        if test.task_config:
            test.task_config_pretty = json.dumps(test.task_config, indent=2)
        else:
            test.task_config_pretty = "{}"

    test_sessions = db.list_test_sessions()


    return render(request, "test_harness/index.html", {
        "available_tests": available_tests,
        "sessions": test_sessions
    })

def session_index(request, session_id):
    db = Database()
    # Fetch the session and join the runs and test metadata in one go
    session_data = db.get_test_session(session_id)

    if not session_data:
        messages.error(request, "Session not found.")
        return redirect("test_harness_index")

    return render(request, "test_harness/session.html", {
        "session": session_data,
        "runs": session_data.runs # This is available via the relationship()
    })

@require_POST
def delete_test_session(request, session_id):
    db = Database()
    try:
        db.delete_test_session(session_id)
        messages.success(request, f"Session #{session_id} deleted.")
    except Exception as e:
        messages.error(request, f"Error deleting session: {str(e)}")
        
    return redirect("test_harness")


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request, page=1):
    page = int(page)
    if page == 0:
        page = 1
    off = (page - 1) * TEST_LIMIT

    test_sessions = []
    available_tests = []

    db_test_sessions = db.list_test_sessions(limit=TEST_LIMIT, offset=off)
    db_available_tests = db.list_available_tests(limit=TEST_LIMIT, offset=off)

    # Vars to define when to show Next/Previous buttons
    paging = {}
    paging["show_session_next"] = "show"
    paging["show_test_next"] = "show"
    paging["next_page"] = str(page + 1)
    paging["prev_page"] = str(page - 1)

    pages_sessions_num = 0
    pages_tests_num = 0
    test_sessions_number = db.count_test_sessions() or 0
    tests_available_number = db.count_available_tests() or 0
    if test_sessions_number:
        pages_sessions_num = int(test_sessions_number / TEST_LIMIT + 1)
    if tests_available_number:
        pages_tests_num = int(tests_available_number / TEST_LIMIT + 1)

    sessions_pages = []
    tests_pages = []
    if pages_sessions_num < 11 or page < 6:
        sessions_pages = list(range(1, min(10, pages_sessions_num) + 1))
    elif page > 5:
        sessions_pages = list(range(min(page - 5, pages_sessions_num - 10) + 1, min(page + 5, pages_sessions_num) + 1))
    if pages_tests_num < 11 or page < 6:
        tests_pages = list(range(1, min(10, pages_tests_num) + 1))
    elif page > 5:
        tests_pages = list(range(min(page - 5, pages_tests_num - 10) + 1, min(page + 5, pages_tests_num) + 1))

    first_session = 0
    first_test = 0
    # On a fresh install, we need handle where there are 0 tests.
    if test_sessions_number > 0:
        first_session = db.list_test_sessions(limit=1,order_by=TestSession.added_on.asc())[0].to_dict()[
            "id"
        ]
        paging["show_session_prev"] = "show"
    else:
        paging["show_session_prev"] = "hide"

    if tests_available_number > 0:
        first_test = db.list_tasks(limit=1, category="static", not_status=TASK_PENDING, order_by=AvailableTest.added_on.asc())[
            0
        ].to_dict()["id"]
        paging["show_test_prev"] = "show"
    else:
        paging["show_test_prev"] = "hide"

    if db_test_sessions:
        for session in db_test_sessions:
            new = get_test_session_info(db, session=session)
            if new["id"] == first_session:
                paging["show_session_next"] = "hide"
            if page <= 1:
                paging["show_session_prev"] = "hide"
            else:
                paging["show_session_prev"] = "show"
            #if db.view_errors(session.id):
            #    new["errors"] = True

            test_sessions.append(new)
    else:
        paging["show_session_next"] = "hide"

    if db_available_tests:
        for test in db_available_tests:
            new = get_test_metadata(db, test=test)
            if new["id"] == first_test:
                paging["show_test_next"] = "hide"
            if page <= 1:
                paging["show_test_prev"] = "hide"
            else:
                paging["show_test_prev"] = "show"
            available_tests.append(new)
    else:
        paging["show_test_next"] = "hide"

    paging["sessions_page_range"] = sessions_pages
    paging["tests_page_range"] = tests_pages
    paging["current_page"] = page
    available_tests.sort(key=lambda x: x["name"], reverse=True)
    test_sessions.sort(key=lambda x: x["id"], reverse=True)
    return render(
        request,
        "test_harness/index.html",
        {
            "title": "Testing",
            "sessions": test_sessions,
            "tests": available_tests,
            "paging": paging,
            "config": enabledconf,
        },
    )