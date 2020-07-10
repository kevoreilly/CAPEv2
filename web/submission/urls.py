# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from django.conf.urls import url
from submission import views

urlpatterns = [
    url(r"^$", views.index, name="submission"),
    url(r"^resubmit/(?P<resubmit_hash>[\w\d]{64})/$", views.index, name="submission"),
    url(r"status/(?P<task_id>\d+)/$", views.status, name="submission_status"),
]
