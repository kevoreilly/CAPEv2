# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from django.urls import path

from submission import views

urlpatterns = [
    path("", views.index, name="submission"),
    path("resubmit/<int:task_id>/<str:resubmit_hash>/", views.index, name="submission"),
    path("status/<int:task_id>/", views.status, name="submission_status"),
    path("remote_session/<int:task_id>/", views.remote_session, name="remote_session"),
]
