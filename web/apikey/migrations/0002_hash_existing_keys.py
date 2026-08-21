"""Convert any existing plaintext API keys to their SHA-256 hash in place.

Keys are now stored hashed (see apikey.models.hash_key). Existing rows hold the
raw 43-char token; re-hashing them keeps every already-issued key working — the
client still presents the same raw value, which now hashes to the stored digest.
Idempotent: rows that already look like a SHA-256 hex digest are left alone.
"""

import hashlib

from django.db import migrations

_HEX = set("0123456789abcdef")


def _looks_hashed(value: str) -> bool:
    return len(value) == 64 and set(value) <= _HEX


def hash_existing_keys(apps, schema_editor):
    ApiKey = apps.get_model("apikey", "ApiKey")
    for row in ApiKey.objects.all().iterator():
        if _looks_hashed(row.key):
            continue
        row.key = hashlib.sha256(row.key.encode()).hexdigest()
        row.save(update_fields=["key"])


def noop_reverse(apps, schema_editor):
    # Hashing is one-way; the raw keys cannot be recovered.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("apikey", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(hash_existing_keys, noop_reverse),
    ]
