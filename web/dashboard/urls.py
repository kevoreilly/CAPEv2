# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.urls import re_path

from dashboard import views

urlpatterns = [
    re_path(r"^$", views.index),
]
