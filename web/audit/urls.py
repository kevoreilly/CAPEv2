# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.urls import re_path, path
from audit import views

urlpatterns = [
    re_path(r"^$", views.audit_index, name="audit_index"),
    re_path(r"^page/(?P<page>\d+)/$", views.audit_index, name="audit_index"),
    re_path(r"^session/(?P<session_id>\d+)/$", views.session_index, name="test_session"),
    re_path(r"^session/(?P<session_id>\d+)/status$", views.session_status, name="session_status"),
    re_path(r"^session/(?P<session_id>\d+)/run_update/<int:testrun_id>/", views.get_run_update, name="get_run_update"),
    re_path(r"^reload_available_tests/", views.reload_available_tests, name="reload_available_tests"),
    re_path(r"^create_test_session/$", views.create_test_session, name="create_test_session"),
    re_path(r"^delete_test_session/(?P<session_id>\d+)/$", views.delete_test_session, name="delete_test_session"),
    path(r"session/<int:session_id>/queue_tests/", views.queue_all_tests, name="queue_all_tests"),
    path(r"session/<int:session_id>/unqueue_tests/", views.unqueue_all_tests, name="unqueue_all_tests"),
    path(r"session/<int:session_id>/queue_tests/<int:testrun_id>/", views.queue_test, name="queue_test"),
    path(r"session/<int:session_id>/unqueue_tests/<int:testrun_id>/", views.unqueue_test, name="unqueue_test"),
    re_path(r"^update_task_config/(?P<availabletest_id>\d+)/$", views.update_task_config, name="update_task_config")
]
