"""Per-user API keys for CAPE's REST API.

Decoupled from DRF's built-in `Token` (which is one-token-per-user) so
each operator / script / CI bot can have its own labeled credential and
revoke any of them independently. Authentication remains the standard
``Authorization: Token <key>`` header for drop-in compatibility with
existing CAPE clients.
"""

import secrets
from django.conf import settings
from django.db import models


def _generate_key() -> str:
    """43-char URL-safe key with ~256 bits of entropy. Long enough that
    even an attacker enumerating against the indexed `key` column has no
    realistic shot, short enough to fit cleanly in an Authorization header."""
    return secrets.token_urlsafe(32)


class ApiKey(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    name = models.CharField(
        max_length=100,
        help_text="A human-readable label (e.g. 'ci-bot', 'personal-laptop').",
    )
    key = models.CharField(max_length=64, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Set when the key is explicitly revoked OR when the owner is disabled. "
        "A non-null value means the key MUST NOT authenticate.",
    )

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            # Fast lookup of a user's active keys for the "my keys" page.
            models.Index(fields=["user", "revoked_at"]),
        ]

    def __str__(self):
        return f"{self.user.username}:{self.name}"

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    @classmethod
    def issue(cls, user, name: str) -> "ApiKey":
        """Create a new key for `user` with the given label. Caller is
        responsible for showing the raw `key` to the operator exactly
        once — we don't display it again after creation."""
        return cls.objects.create(user=user, name=name, key=_generate_key())
