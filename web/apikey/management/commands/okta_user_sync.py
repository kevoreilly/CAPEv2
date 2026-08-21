"""Management command: reconcile local Django User.is_active with Okta status.

For every Django User that has at least one active ApiKey AND a linked OIDC
SocialAccount, look the user up in Okta by email. If Okta no longer reports
the user as ACTIVE (status SUSPENDED, DEPROVISIONED, LOCKED_OUT, ...) or
returns no result for the email, deactivate the local user — which fires
the post_save cascade-revoke signal and invalidates all of their API keys.

Run periodically via systemd timer (cape-okta-sync.timer) to bound the gap
between Okta-side disable/revoke and local API access being cut off.

Configuration (web.conf [oauth_oidc]):
  admin_api_url    = https://<your-okta-org>.okta.com
  admin_api_token  = <SSWS token with okta.users.read scope>

Usage:
  poetry run python manage.py okta_user_sync           # apply changes
  poetry run python manage.py okta_user_sync --dry-run # report only
"""

import logging

import requests
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from allauth.socialaccount.models import SocialAccount
from apikey.models import ApiKey
from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Reconcile local User.is_active with Okta status; cascade-revoke ApiKeys for users no longer ACTIVE in Okta."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="report what would change without modifying users",
        )

    def handle(self, *args, **opts):
        web_cfg = Config("web")
        oidc_cfg = getattr(web_cfg, "oauth_oidc", None)
        if not oidc_cfg or not oidc_cfg.get("enabled", False):
            self.stderr.write("[oauth_oidc] is not enabled — nothing to sync")
            return

        admin_url = (oidc_cfg.get("admin_api_url") or "").rstrip("/")
        admin_token = oidc_cfg.get("admin_api_token") or ""
        if not admin_url or not admin_token:
            self.stderr.write(
                "[oauth_oidc] admin_api_url or admin_api_token missing — set them in web.conf to enable Okta sync"
            )
            return

        # Find users that (a) have at least one active ApiKey and
        # (b) have a linked SocialAccount (i.e., were JIT-provisioned via
        # Okta SSO). Local-only admin accounts with API keys are skipped.
        active_apikey_user_ids = set(
            ApiKey.objects.filter(revoked_at__isnull=True).values_list("user_id", flat=True)
        )
        sso_user_ids = set(SocialAccount.objects.values_list("user_id", flat=True))
        target_ids = active_apikey_user_ids & sso_user_ids
        users = list(User.objects.filter(id__in=target_ids, is_active=True))
        if not users:
            self.stdout.write("no SSO users with active API keys to check")
            return

        self.stdout.write(f"checking {len(users)} SSO users with active ApiKeys against Okta")

        session = requests.Session()
        session.headers.update(
            {
                "Authorization": f"SSWS {admin_token}",
                "Accept": "application/json",
                "User-Agent": "CAPE/okta_user_sync",
            }
        )

        deactivated = 0
        for user in users:
            email = (user.email or "").strip()
            if not email:
                self.stderr.write(f"  user_id={user.id} ({user.username}): no email on local record — skipping")
                continue

            try:
                # search filter — exact email match. URL-quoting is handled by
                # requests; escape backslashes and quotes so an address with
                # those characters can't break the SCIM filter syntax.
                safe_email = email.replace("\\", "\\\\").replace('"', '\\"')
                r = session.get(
                    f"{admin_url}/api/v1/users",
                    params={"search": f'profile.email eq "{safe_email}"'},
                    timeout=10,
                )
                r.raise_for_status()
                results = r.json()
            except Exception as e:
                self.stderr.write(f"  {email}: Okta lookup failed: {e}")
                continue

            if not isinstance(results, list) or not results:
                # Email not found in Okta — user has been deleted there.
                if self._deactivate(user, "okta_user_not_found", opts["dry_run"]):
                    deactivated += 1
                continue

            okta_user = results[0]
            status = (okta_user.get("status") or "").upper()
            if status != "ACTIVE":
                if self._deactivate(user, f"okta_status_{status or 'UNKNOWN'}", opts["dry_run"]):
                    deactivated += 1
            else:
                self.stdout.write(f"  {email}: ACTIVE")

        suffix = " (dry run)" if opts["dry_run"] else ""
        self.stdout.write(self.style.SUCCESS(f"sync complete{suffix} — {deactivated} user(s) deactivated"))

    def _deactivate(self, user, reason, dry_run):
        msg = f"  {user.email}: deactivating (reason={reason})"
        if dry_run:
            self.stdout.write(self.style.WARNING(f"{msg} [DRY RUN]"))
            return False
        user.is_active = False
        user.save()  # triggers the post_save cascade-revoke signal in apikey.signals
        self.stdout.write(self.style.WARNING(msg))
        log.warning("okta_user_sync: deactivated user %s reason=%s", user.username, reason)
        return True
