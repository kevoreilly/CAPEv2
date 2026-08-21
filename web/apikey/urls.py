from django.urls import path

from . import views

app_name = "apikey"

urlpatterns = [
    path("", views.list_view, name="list"),
    path("create/", views.create_view, name="create"),
    path("<int:pk>/revoke/", views.revoke_view, name="revoke"),
]
