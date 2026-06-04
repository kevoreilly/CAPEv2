"""User-facing views for managing API keys.

All views require an authenticated session — keys are scoped to the
logged-in user. The raw key value is shown EXACTLY ONCE on creation;
afterwards only the redacted form (last 4 chars) appears in the UI.

Authorization model:
  - Local users (no SocialAccount link): always permitted to manage
    their own keys. Service accounts and break-glass admins live here.
  - SSO users with is_staff=True: permitted. The OIDC adapter promotes
    members of the configured admin/superadmin groups; everyone else
    has no programmatic API access.
  - SSO users without staff: denied. Programmatic API access for these
    users is issued out-of-band (admin creates a service account on
    their behalf, or admin creates a key for them in Django admin).
"""

from allauth.socialaccount.models import SocialAccount
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .forms import ApiKeyCreateForm
from .models import ApiKey


def _user_may_manage_keys(user):
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


def _forbidden(request):
    return render(request, "apikey/forbidden.html", status=403)


@login_required
def list_view(request):
    if not _user_may_manage_keys(request.user):
        return _forbidden(request)
    keys = ApiKey.objects.filter(user=request.user).order_by("-created_at")
    # `flash_key` lets the create view hand the freshly-issued raw key
    # to the list page through the session — we never re-display it
    # after the page is reloaded.
    flash_key = request.session.pop("apikey_flash", None)
    return render(request, "apikey/list.html", {"keys": keys, "flash_key": flash_key})


@login_required
def create_view(request):
    if not _user_may_manage_keys(request.user):
        return _forbidden(request)
    if request.method == "POST":
        form = ApiKeyCreateForm(request.POST)
        if form.is_valid():
            apikey, raw_key = ApiKey.issue(user=request.user, name=form.cleaned_data["name"])
            # Stash the raw key in the session so we can show it once on the
            # list page and then forget it (only its hash is stored, so this is
            # the only moment we ever have the raw value). Avoids the "save my
            # key" being lost if the user navigates away from the create page.
            request.session["apikey_flash"] = {
                "name": apikey.name,
                "key": raw_key,
            }
            messages.success(request, f"API key '{apikey.name}' created.")
            return redirect("apikey:list")
    else:
        form = ApiKeyCreateForm()
    return render(request, "apikey/create.html", {"form": form})


@login_required
@require_POST
def revoke_view(request, pk):
    if not _user_may_manage_keys(request.user):
        return _forbidden(request)
    apikey = get_object_or_404(ApiKey, pk=pk, user=request.user)
    if apikey.revoked_at is None:
        apikey.revoked_at = timezone.now()
        apikey.save(update_fields=["revoked_at"])
        messages.success(request, f"API key '{apikey.name}' revoked.")
    else:
        messages.info(request, f"API key '{apikey.name}' was already revoked.")
    return redirect("apikey:list")
