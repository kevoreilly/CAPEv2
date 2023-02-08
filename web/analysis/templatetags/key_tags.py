from django import template

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
