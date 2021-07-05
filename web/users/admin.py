from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from .models import UserProfile

# Django 3.2
# @admin.action(description='Mark selected stories as published')
def make_active(modeladmin, news, queryset):
    queryset.update(is_active=True)
make_active.short_description = u"Activate selected Users"

def make_deactivated(modeladmin, news, queryset):
    queryset.update(is_active=False)
make_deactivated.short_description = u"Deactivate selected Users"

class ProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'

class CustomUserAdmin(UserAdmin):
    inlines = (ProfileInline, )
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'get_suscription')
    list_select_related = ('userprofile', )
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups', 'emailaddress__verified')
    actions = (make_active, make_deactivated)

    def get_suscription(self, instance):
        return instance.userprofile.suscription
    get_suscription.short_description = 'Suscription'

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)


admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
