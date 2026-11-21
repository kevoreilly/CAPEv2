from django import template

from lib.cuckoo.common.cape_utils import sort_dumps_by_detection

register = template.Library()


@register.filter(name="getkey")
def getkey(mapping, value):
    if isinstance(mapping, dict):
        return mapping.get(value, "")


@register.filter(name="gettype")
def gettype(value):
    return str(type(value))


@register.filter(name="str2list")
def str2list(value):
    if isinstance(value, str):
        return [value]
    return value


@register.filter(name="dict2list")
def dict2list(value):
    if isinstance(value, dict):
        return [value]
    return value


@register.filter(name="parentfixup")
def parentfixup(value):
    if "file_size" in value:
        value["size"] = value["file_size"]
    if "name" not in value:
        value["name"] = value["sha256"]
    return value


@register.filter(name="sort_dumps")
def sort_dumps(value):
    return sort_dumps_by_detection(value)

