from django.contrib import admin
from django.utils import timezone

from .models import ApiKey


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = ("name", "user", "created_at", "last_used_at", "revoked_at")
    list_filter = ("revoked_at",)
    search_fields = ("name", "user__username", "user__email")
    readonly_fields = ("key", "created_at", "last_used_at")
    actions = ("revoke_selected",)

    @admin.action(description="Revoke selected keys")
    def revoke_selected(self, request, queryset):
        n = queryset.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())
        self.message_user(request, f"Revoked {n} API key(s).")
