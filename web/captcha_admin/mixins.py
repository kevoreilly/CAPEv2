from django.contrib.admin.sites import site as default_site


class AdminSiteRegistryFix(object):
    """
    This fix links the '_registry' property to the original AdminSites
    '_registry' property. This is necessary, because of the character of
    the admins 'autodiscover' function. Otherwise the admin site will say,
    that you haven't permission to edit anything.
    """

    def _registry_getter(self):
        return default_site._registry

    def _registry_setter(self, value):
        default_site._registry = value

    _registry = property(_registry_getter, _registry_setter)
