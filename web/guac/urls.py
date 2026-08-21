from django.urls import path, re_path

from guac import views

urlpatterns = [
    re_path(r"^(?P<task_id>\d+)/(?P<session_data>[\w=]+)/$", views.index, name="index"),
    path("direct/vnc/<str:host>/<int:port>/", views.direct_vnc_host_port, name="direct_vnc_host_port"),
    path("direct/vnc/<str:vm_name>/", views.direct_vnc_vm, name="direct_vnc_vm"),
    path("direct/vnc/<str:vm_name>/start/", views.direct_vnc_vm_start, name="direct_vnc_vm_start"),
    path("direct/vnc/<str:vm_name>/shutdown/", views.direct_vnc_vm_shutdown, name="direct_vnc_vm_shutdown"),
    path("direct/vnc/<str:vm_name>/route/", views.direct_vnc_vm_route, name="direct_vnc_vm_route"),
    path("direct/vnc/<str:vm_name>/snapshots/", views.direct_vnc_vm_snapshots_list, name="direct_vnc_vm_snapshots_list"),
    path("direct/vnc/<str:vm_name>/snapshot/create/", views.direct_vnc_vm_snapshot_create, name="direct_vnc_vm_snapshot_create"),
    path("direct/vnc/<str:vm_name>/snapshot/delete/", views.direct_vnc_vm_snapshot_delete, name="direct_vnc_vm_snapshot_delete"),
]

