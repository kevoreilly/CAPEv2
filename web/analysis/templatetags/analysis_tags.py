from __future__ import absolute_import
import six

try:
    import re2 as re
except ImportError:
    import re

from django.template.defaultfilters import register
from collections import OrderedDict


@register.filter("mongo_id")
def mongo_id(value):
    """Retrieve _id value.
    @todo: it will be removed in future.
    """
    if isinstance(value, dict):
        if "_id" in value:
            value = value["_id"]

    # Return value
    return six.text_type(value)


@register.filter("is_dict")
def is_dict(value):
    """Checks if value is an instance of dict"""
    return isinstance(value, dict)


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key, "")


@register.filter(name="dehex")
def dehex(value):
    return re.sub(r"\\x[0-9a-f]{2}", "", value)


@register.filter(name="stats_total")
def stats_total(value):
    total = float()
    for item in value:
        total += item["time"]

    return total


@register.filter(name="sort")
def sort(value):
    if isinstance(value, dict):
        sorteddict = OrderedDict()
        sortedkeys = sorted(value.keys())
        for key in sortedkeys:
            sorteddict[key] = value[key]
        return sorteddict
    return value


@register.filter(name="format_cli")
def format_cli(cli, length):
    if cli.startswith('"'):
        ret = " ".join(cli[cli[1:].index('"') + 2 :].split()).strip()
    else:
        ret = " ".join(cli.split()[1:]).strip()
    if len(ret) >= length + 15:
        ret = ret[:length] + " ...(truncated)"
    # Return blank string instead of 'None'
    if not ret:
        return ""
    return ret
