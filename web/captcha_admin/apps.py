from django.contrib.admin.apps import AdminConfig as _AdminConfig


class AdminConfig(_AdminConfig):
    """
    Inherit Django AdminConfig. We want the autodiscover feature. Do not define your default_site according to the
    Django docs. Otherwise, we will end up with a recursive import error when loading this module.
    """
    pass
