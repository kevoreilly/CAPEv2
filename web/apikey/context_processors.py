"""Template context processor — surfaces apikey access policy to templates."""

from .views import _user_may_manage_keys


def apikey_access(request):
    """Make `may_manage_apikeys` available to every template, so the user
    dropdown can hide the API Keys link for SSO non-staff users."""
    return {"may_manage_apikeys": _user_may_manage_keys(getattr(request, "user", None))}
