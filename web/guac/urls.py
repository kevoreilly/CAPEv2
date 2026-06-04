from django.urls import path, re_path

from guac import views

urlpatterns = [
    re_path(r"^(?P<task_id>\d+)/(?P<session_data>[\w=]+)/$", views.index, name="index"),
    path("direct/vnc/<str:host>/<int:port>/", views.direct_vnc_host_port, name="direct_vnc_host_port"),
    path("direct/vnc/<str:vm_name>/", views.direct_vnc_vm, name="direct_vnc_vm"),
]

