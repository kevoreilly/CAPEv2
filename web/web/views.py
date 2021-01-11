from ratelimit.exceptions import Ratelimited
from django.shortcuts import redirect, render
from django.conf import settings
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages

def handler403(request, exception=None):
    if isinstance(exception, Ratelimited):
        return render(request, "error.html", {"error": settings.RATELIMIT_ERROR_MSG}, status=429)
    return render(request, "error.html", {"error": 'Forbidden'}, status=403)
