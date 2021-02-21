# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import sys

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_safe
from django.contrib.auth.decorators import login_required

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_RUNNING, TASK_DISTRIBUTED
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_RECOVERED
from lib.cuckoo.core.database import TASK_REPORTED, TASK_FAILED_ANALYSIS
from lib.cuckoo.core.database import TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING
from lib.cuckoo.common.web_utils import top_detections

# Conditional decorator for web authentication
class conditional_login_required(object):
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition

    def __call__(self, func):
        if not self.condition:
            return func
        return self.decorator(func)


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request):
    db = Database()

    report = dict(total_samples=db.count_samples(), total_tasks=db.count_tasks(), states_count={}, estimate_hour=None, estimate_day=None)

    states = (
        TASK_PENDING,
        TASK_RUNNING,
        TASK_DISTRIBUTED,
        TASK_COMPLETED,
        TASK_RECOVERED,
        TASK_REPORTED,
        TASK_FAILED_ANALYSIS,
        TASK_FAILED_PROCESSING,
        TASK_FAILED_REPORTING,
    )

    for state in states:
        report["states_count"][state] = db.count_tasks(state)

    # For the following stats we're only interested in completed tasks.
    tasks = db.count_tasks(status=TASK_COMPLETED)
    tasks += db.count_tasks(status=TASK_REPORTED)

    if tasks:
        # Get the time when the first task started and last one ended.
        started, completed = db.minmax_tasks()

        # It has happened that for unknown reasons completed and started were
        # equal in which case an exception is thrown, avoid this.
        if started and completed and int(completed - started):
            hourly = 60 * 60 * tasks / (completed - started)
        else:
            hourly = 0

        report["estimate_hour"] = int(hourly)
        report["estimate_day"] = int(24 * hourly)
        report["top_detections"] = top_detections()

    return render(request, "dashboard/index.html", {"report": report})
