import os

from django.conf import settings
from django.http import FileResponse
from django.shortcuts import redirect, render

try:
    from django_ratelimit.exceptions import Ratelimited
except ImportError:
    try:
        from ratelimit.exceptions import Ratelimited
    except ImportError:
        print("missed dependency: poetry run pip install django-ratelimit -U")


def handler403(request, exception=None):
    if isinstance(exception, Ratelimited):
        return render(request, "error.html", {"error": settings.RATELIMIT_ERROR_MSG}, status=429)
    return render(request, "error.html", {"error": "Forbidden"}, status=403)


def handler404(request, exception=None):
    return redirect("/")


def serve_agent(request):
    agent_path = os.path.join(settings.BASE_DIR, "..", "agent", "agent.py")
    return FileResponse(open(agent_path, "rb"), filename="agent.py", content_type="text/x-python")
