from __future__ import absolute_import

from django import template

register = template.Library()


@register.filter(name="getkey")
def getkey(mapping, value):
    if isinstance(mapping, dict):
        return mapping.get(value, "")


@register.filter(name="str2list")
def str2list(value):
    if isinstance(value, str):
        return [value]
    return value
