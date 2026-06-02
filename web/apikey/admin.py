from django.contrib import admin, messages
from django.utils import timezone

from .models import ApiKey, _generate_key, hash_key


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = ("name", "user", "created_at", "last_used_at", "revoked_at")
    list_filter = ("revoked_at",)
    search_fields = ("name", "user__username", "user__email")
    readonly_fields = ("key", "created_at", "last_used_at")
    actions = ("revoke_selected",)

    def save_model(self, request, obj, form, change):
        # `key` is readonly with no model default, so a key created through the
        # admin add-form would otherwise hit a NOT NULL/unique violation. Mint
        # and hash one here, and surface the raw value to the admin exactly once.
        if not change and not obj.key:
            raw = _generate_key()
            obj.key = hash_key(raw)
            self.message_user(
                request,
                f"API key '{obj.name}' created. Raw key: {raw} — copy it now; it will not be shown again.",
                level=messages.WARNING,
            )
        super().save_model(request, obj, form, change)

    @admin.action(description="Revoke selected keys")
    def revoke_selected(self, request, queryset):
        n = queryset.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())
        self.message_user(request, f"Revoked {n} API key(s).")
