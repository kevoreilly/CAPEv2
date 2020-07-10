from __future__ import absolute_import
from django import template

register = template.Library()


@register.filter(name="datefmt")
def datefmt(value):
    formatted = (
        value[2:6] + "/" + value[6:8] + "/" + value[8:10] + " " + value[10:12] + ":" + value[12:14] + ":" + value[14:16] + " GMT" + value[16:19]
    )
    return formatted
