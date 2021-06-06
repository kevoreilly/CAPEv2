from django.shortcuts import render, redirect
from django.conf import settings

try:
    from django_ratelimit.exceptions import Ratelimited
except ImportError:
    try:
        from ratelimit.exceptions import Ratelimited
    except ImportError:
        print("missed dependency: pip3 install django-ratelimit -U")


def handler403(request, exception=None):
    if isinstance(exception, Ratelimited):
        return render(request, "error.html", {"error": settings.RATELIMIT_ERROR_MSG}, status=429)
    return render(request, "error.html", {"error": 'Forbidden'}, status=403)

def handler404(request, exception=None):
    return redirect("/")
