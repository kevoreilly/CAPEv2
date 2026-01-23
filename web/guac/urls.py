from django.urls import re_path

from guac import views

urlpatterns = [
    re_path(r"^(?P<task_id>\d+)/(?P<session_data>[\w=]+)/$", views.index, name="index"),
]
