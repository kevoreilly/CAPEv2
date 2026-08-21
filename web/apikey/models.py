"""Per-user API keys for CAPE's REST API.

Decoupled from DRF's built-in `Token` (which is one-token-per-user) so
each operator / script / CI bot can have its own labeled credential and
revoke any of them independently. Authentication remains the standard
``Authorization: Token <key>`` header for drop-in compatibility with
existing CAPE clients.
"""

import hashlib
import secrets
from django.conf import settings
from django.db import models


def _generate_key() -> str:
    """43-char URL-safe raw key with ~256 bits of entropy — shown to the
    operator exactly once and never stored. Only its hash (see `hash_key`)
    is persisted, so a database leak doesn't expose usable credentials."""
    return secrets.token_urlsafe(32)


def hash_key(raw: str) -> str:
    """SHA-256 hex digest of a raw key (what we store and look up by).
    Raw keys are high-entropy random tokens, so an unsalted SHA-256 is
    sufficient — there is no low-entropy secret to brute-force."""
    return hashlib.sha256(raw.encode()).hexdigest()


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
    # Stores the SHA-256 hex digest of the raw key (64 chars), never the raw key.
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
    def issue(cls, user, name: str) -> tuple["ApiKey", str]:
        """Create a new key for `user` with the given label. Returns
        ``(obj, raw_key)``: only the hash is stored, so the caller MUST show
        the raw key to the operator exactly once — it can never be recovered."""
        raw = _generate_key()
        obj = cls.objects.create(user=user, name=name, key=hash_key(raw))
        return obj, raw
