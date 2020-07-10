from __future__ import absolute_import
from django import template

register = template.Library()


@register.filter(name="getkey")
def getkey(mapping, value):
    return mapping.get(value, "")
