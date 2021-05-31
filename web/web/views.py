from django.shortcuts import render, redirect

def handler403(request, exception=None):
    return render(request, "error.html", {"error": 'Forbidden'}, status=403)

def handler404(request, exception=None):
    return redirect("/")
