import logging

from django.shortcuts import redirect

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

try:  # django 1.10+
    from django.utils.deprecation import MiddlewareMixin
except ImportError:

    class MiddlewareMixin:
        def __init__(self, get_response=None):
            pass


# You can learn more from those
# https://docs.djangoproject.com/en/dev/topics/http/middleware/#process-request
# https://simpleisbetterthancomplex.com/tutorial/2016/07/18/how-to-create-a-custom-django-middleware.html

redirect_url = "https://your_custom_auth_server?redirrect="

# you need to uncomment in web/web/settings.py in Section MIDDLEWARE list -> "web.middleware.CustoAuth",


class CustomAuth(MiddlewareMixin):
    def check_auth(self, request):
        """Place custom auth logic here
        Return True on authentificated user
        Return False on need auth
        Cookie access via - request.COOKIES - dict
        """
        return True

    def process_view(self, request, view_function, view_args, view_kwargs):
        # One-time configuration and initialization.
        # return None - means disable auth, redirrect if need auth
        # Disable auth
        if getattr(view_function, "csrf_exempt", False):
            return None

        request_url = request.build_absolute_uri()
        # Custom auth verification logic goes here, redirrect if Auth required
        if self.check_auth(request):
            return None
        return redirect(redirect_url + request_url)
