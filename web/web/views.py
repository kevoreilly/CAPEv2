from django.shortcuts import render

def handler403(request, exception=None):
    return render(request, "error.html", {"error": 'Forbidden'}, status=403)
