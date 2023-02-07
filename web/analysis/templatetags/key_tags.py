from django import template

register = template.Library()


@register.filter(name="getkey")
def getkey(mapping, value):
    if isinstance(mapping, dict):
        return mapping.get(value, "")

#Added: Added function to get type of variable
@register.filter(name="gettype")
def gettype(value):
    return str(type(value))

#Added: Added function to split list
@register.filter(name="split")
def split(value, key):
    return value.split(key)

#Added: Added function to search for keys in nested dictionary
@register.filter(name="findkey")
def findkey(value, key):
    if key in value: return value[key]
    for k, v in value.items():
        if isinstance(v,dict):
            item = findkey(v, key)
            if item is not None:
                return item

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