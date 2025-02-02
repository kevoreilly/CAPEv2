# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.urls import re_path

from submission import views

urlpatterns = [
    re_path(r"^$", views.index, name="submission"),
    re_path(r"^resubmit/(?P<task_id>\d+)/(?P<resubmit_hash>[\w\d]{64})/$", views.index, name="submission"),
    re_path(r"status/(?P<task_id>\d+)/$", views.status, name="submission_status"),
    re_path(r"remote_session/(?P<task_id>\d+)/$", views.remote_session, name="remote_session"),
]
