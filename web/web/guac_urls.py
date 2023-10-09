from django.conf import settings
from django.conf.urls.static import static
from django.urls import include, re_path

urlpatterns = [
    re_path(r"^guac/", include("guac.urls")),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
