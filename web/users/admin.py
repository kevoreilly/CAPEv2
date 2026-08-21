from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from .models import Tenant, UserProfile

# Tenancy-privilege fields: the SOLE authority reconcile_tenant() trusts to assign a user's tenant
# and tenant-admin status on SSO login. Editable only by superusers -- a non-superuser holding a
# delegated change_tenant / change_userprofile grant must NOT be able to escalate (add themselves to
# admin_idp_groups, flip is_tenant_admin, or move a user's tenant). Enforced via get_readonly_fields.
_TENANT_PRIV_FIELDS = ("idp_groups", "admin_idp_groups")
_PROFILE_PRIV_FIELDS = ("tenant", "is_tenant_admin")


# Django 3.2
# @admin.action(description='Mark selected stories as published')
def make_active(modeladmin, news, queryset):
    queryset.update(is_active=True)


make_active.short_description = "Activate selected Users"


def make_deactivated(modeladmin, news, queryset):
    queryset.update(is_active=False)


make_deactivated.short_description = "Deactivate selected Users"


class ProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = "Profile"
    fk_name = "user"

    def get_readonly_fields(self, request, obj=None):
        ro = tuple(super().get_readonly_fields(request, obj))
        if not request.user.is_superuser:
            ro = ro + _PROFILE_PRIV_FIELDS  # non-superusers can't set a user's tenant / tenant-admin
        return ro


class CustomUserAdmin(UserAdmin):
    inlines = (ProfileInline,)
    list_display = ("username", "email", "first_name", "last_name", "is_staff", "get_subscription")
    list_select_related = ("userprofile",)
    list_filter = ("is_staff", "is_superuser", "is_active", "groups", "emailaddress__verified")
    actions = (make_active, make_deactivated)

    def get_subscription(self, instance):
        return instance.userprofile.subscription

    get_subscription.short_description = "Subscription"

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return []
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ("slug", "name", "active", "created_at")
    search_fields = ("slug", "name")
    list_filter = ("active",)

    def get_readonly_fields(self, request, obj=None):
        ro = tuple(super().get_readonly_fields(request, obj))
        if not request.user.is_superuser:
            ro = ro + _TENANT_PRIV_FIELDS  # non-superusers can't edit the group->tenant/admin maps
        return ro
