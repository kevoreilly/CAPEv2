"""API-key access policy — kept view-independent so both views.py and the
context processor can import it without pulling in view-layer dependencies
(or risking an import cycle)."""

from allauth.socialaccount.models import SocialAccount


def user_may_manage_keys(user):
    """Return True if `user` is allowed to view/create/revoke their own keys.
    Local-only users always pass; SSO-provisioned users must be staff."""
    if not user or not user.is_authenticated:
        return False
    # Called from the apikey_access context processor on every page load —
    # cache the SocialAccount lookup on the user object for the request to
    # avoid a redundant query per render.
    if not hasattr(user, "_may_manage_keys"):
        is_sso = SocialAccount.objects.filter(user=user).exists()
        user._may_manage_keys = True if not is_sso else bool(user.is_staff)
    return user._may_manage_keys
