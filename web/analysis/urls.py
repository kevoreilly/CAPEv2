# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from analysis import views
from django.urls import re_path

urlpatterns = [
    re_path(r"^$", views.index, name="analysis"),
    re_path(r"^page/(?P<page>\d+)/$", views.index, name="index"),
    re_path(r"^(?P<task_id>\d+)/$", views.report, name="report"),
    re_path(r"^load_files/(?P<task_id>\d+)/(?P<category>\w+)/$", views.load_files, name="load_files"),
    re_path(r"^surialert/(?P<task_id>\d+)/$", views.surialert, name="surialert"),
    re_path(r"^surihttp/(?P<task_id>\d+)/$", views.surihttp, name="surihttp"),
    re_path(r"^suritls/(?P<task_id>\d+)/$", views.suritls, name="suritls"),
    re_path(r"^surifiles/(?P<task_id>\d+)/$", views.surifiles, name="surifiles"),
    re_path(r"^antivirus/(?P<task_id>\d+)/$", views.antivirus, name="antivirus"),
    re_path(r"^shrike/(?P<task_id>\d+)/$", views.shrike, name="shrike"),
    re_path(r"^remove/(?P<task_id>\d+)/$", views.remove, name="remove"),
    re_path(r"^signature-calls/(?P<task_id>\d+)/$", views.signature_calls, name="signature-calls"),
    re_path(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$", views.chunk, name="chunk"),
    re_path(
        r"^filtered/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<category>\w+)/(?P<apilist>[!]?[A-Za-z_0-9,%]*)/(?P<caller>\w+)/(?P<tid>\w+)/$",
        views.filtered_chunk,
        name="filtered_chunk",
    ),
    re_path(r"^file_nl/(?P<category>\w+)/(?P<task_id>\d+)/(?P<dlfile>\w+)/$", views.file_nl, name="file_nl"),
    re_path(r"^search/(?P<task_id>\d+)/$", views.search_behavior, name="search_behavior"),
    re_path(r"^search/(?P<searched>[\w\d\s:\-_]+)/$", views.search, name="search"),
    re_path(r"^search/$", views.search, name="search"),
    re_path(r"^pending/$", views.pending, name="pending"),
    re_path(r"^ban_user_tasks/(?P<user_id>[\d]+)/$", views.ban_all_user_tasks, name="ban_all_user_tasks"),
    re_path(r"^ban_user/(?P<user_id>[\d]+)/$", views.ban_user, name="ban_user"),
    re_path(r"^procdump/(?P<task_id>\d+)/(?P<process_id>\d+)/(?P<start>\w+)/(?P<end>\w+)/$", views.procdump, name="procdump"),
    re_path(
        r"^procdump/(?P<task_id>\d+)/(?P<process_id>\d+)/(?P<start>\w+)/(?P<end>\w+)/(?P<zipped>\d)/$",
        views.procdump,
        name="procdump",
    ),
    re_path(r"^(?P<task_id>\d+)/pcapstream/(?P<conntuple>[.,\w]+)/$", views.pcapstream, name="pcapstream"),
    re_path(r"^(?P<task_id>\d+)/comments/$", views.comments, name="comments"),
    re_path(
        r"^on_demand/(?P<service>[\w\-_]+)/(?P<task_id>\d+)/(?P<category>\w+)/(?P<sha256>\w{64})", views.on_demand, name="on_demand"
    ),
]
