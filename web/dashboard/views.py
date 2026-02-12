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

from lib.cuckoo.common.web_utils import top_detections
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.data.task import (
    TASK_COMPLETED,
    TASK_DISTRIBUTED,
    TASK_FAILED_ANALYSIS,
    TASK_FAILED_PROCESSING,
    TASK_FAILED_REPORTING,
    TASK_PENDING,
    TASK_RECOVERED,
    TASK_REPORTED,
    TASK_RUNNING
)


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


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request):
    db: TasksMixIn = Database()

    report = dict(
        total_samples=format_number_with_space(db.count_samples()),
        total_tasks=format_number_with_space(db.count_tasks()),
        states_count={},
        estimate_hour=None,
        estimate_day=None,
    )

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

    data = {"title": "Dashboard", "report": {}}

    if tasks:
        # Get the time when the first task started and last one ended.
        started, completed = db.minmax_tasks()

        # It has happened that for unknown reasons completed and started were
        # equal in which case an exception is thrown, avoid this.
        if started and completed and int(completed - started):
            hourly = 60 * 60 * tasks / (completed - started)
        else:
            hourly = 0

        report["estimate_hour"] = format_number_with_space(int(hourly))
        report["estimate_day"] = format_number_with_space(int(24 * hourly))
        report["top_detections"] = top_detections()

        data["report"] = report
    return render(request, "dashboard/index.html", data)
