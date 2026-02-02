# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.urls import re_path

from test_harness import views

urlpatterns = [
    re_path(r"^$", views.test_harness_index, name="test_harness"),    
    re_path(r"^session/(?P<session_id>\d+)/$", views.session_index, name="test_session"),        
    re_path(r"^reload_available_tests/", views.reload_available_tests, name="reload_available_tests"),
    re_path(r"^create_test_session/$", views.create_test_session, name="create_test_session"),
    re_path(r"^delete_test_session/(?P<session_id>\d+)/$", views.delete_test_session, name="delete_test_session"),
]
