# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from __future__ import absolute_import

from dashboard import views
from django.conf.urls import url

urlpatterns = [
    url(r"^$", views.index),
]
