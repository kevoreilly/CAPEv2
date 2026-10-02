# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.urls import path
from audit import views

urlpatterns = [
    path("", views.audit_index, name="audit_index"),
    path("page/<int:page>/", views.audit_index, name="audit_index"),
    path("session/<int:session_id>/", views.session_index, name="test_session"),
    path("session/<int:session_id>/status", views.session_status, name="session_status"),
    path("session/<int:session_id>/run_update/<int:testrun_id>/", views.get_run_update, name="get_run_update"),
    path("reload_available_tests/", views.reload_available_tests, name="reload_available_tests"),
    path("create_test_session/", views.create_test_session, name="create_test_session"),
    path("delete_test_session/<int:session_id>/", views.delete_test_session, name="delete_test_session"),
    path("session/<int:session_id>/queue_tests/", views.queue_all_tests, name="queue_all_tests"),
    path("session/<int:session_id>/unqueue_tests/", views.unqueue_all_tests, name="unqueue_all_tests"),
    path("session/<int:session_id>/queue_tests/<int:testrun_id>/", views.queue_test, name="queue_test"),
    path("session/<int:session_id>/unqueue_tests/<int:testrun_id>/", views.unqueue_test, name="unqueue_test"),
    path("update_task_config/<int:availabletest_id>/", views.update_task_config, name="update_task_config")
]
