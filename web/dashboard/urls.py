# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from dashboard import views
from django.urls import re_path

urlpatterns = [
    re_path(r"^$", views.index),
]
