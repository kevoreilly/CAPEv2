# from django.conf import settings
from django.shortcuts import render # redirect
# from django.urls import reverse
from recaptcha.utils import get_recaptcha_response, is_human
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class RecaptchaVerificationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # self.excluded_paths = getattr(settings, 'RECAPTCHA_EXCLUDED_PATHS', [])
        # self.require_recaptcha_paths = getattr(settings, 'RECAPTCHA_REQUIRED_PATHS', [])
        # self.redirect_url = getattr(settings, 'RECAPTCHA_REDIRECT_URL', reverse('recaptcha_failed')) # You'll need to create this URL

    def __call__(self, request):
        # Skip excluded paths
        if request.path.startswith("/apiv2/"): #  in self.excluded_paths:
            return self.get_response(request)

        # Check if the current path requires reCAPTCHA
        # if self.require_recaptcha_paths and request.path not in self.require_recaptcha_paths:
        # if request.path.startswith("/analysis/"):
        #    return self.get_response(request)

        # Only apply reCAPTCHA to POST requests (you can adjust this)
        recaptcha_response = get_recaptcha_response(request)
        human = is_human(recaptcha_response)

        if not human:
            # Optionally log the failure
            # ToDo add fail2ban?
            # X-forward-for

            logger.warning("reCAPTCHA verification failed for IP: %s", request.META.get('REMOTE_ADDR'))
            logger.warning(
                "reCAPTCHA verification failed at %s for IP: %s, URL: %s", datetime.now(), request.META.get('REMOTE_ADDR'), request.path
            )
            return render(request, "error.html", {"error": "reCAPTCHA Verification Failed. Please try again to verify that you are not a robot."})

        response = self.get_response(request)
        return response
