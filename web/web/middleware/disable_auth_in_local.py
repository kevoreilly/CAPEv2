from django.conf import settings


class DisableAllauthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        remote = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "")).split(",")[0].strip()
        if remote in ["127.0.0.1", "::1", "localhost"]:
            # Remove allauth authentication middleware
            settings.MIDDLEWARE = [m for m in settings.MIDDLEWARE if "allauth.account.middleware.AccountMiddleware" not in m]
        response = self.get_response(request)
        return response
