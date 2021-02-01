from __future__ import absolute_import
import os
import six
from io import StringIO

try:
    import re2 as re
except ImportError:
    import re

from collections import OrderedDict
from django.utils.safestring import mark_safe
from django.utils.html import escape
from django.template.defaultfilters import register

@register.filter("network_rn")
def network_rn_func(value):
    """get basename from path"""
    return list(filter(None, value.decode("utf-8").split("\r\n")))


@register.filter("filename")
def filename(value):
    """get basename from path"""
    return os.path.basename(value)

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

@register.filter(name="flare_capa_capability")
def flare_capa_capabilities(obj, *args, **kwargs):
    result = StringIO()
    def _print(lvl, s):
        result.write((lvl * u'  ') + s)

    _print(1, '<table class="table table-striped table-hover table-bordered">\n')
    _print(1, '<thead>\n')
    _print(1, '<tr>\n')
    _print(1, '<th scope="col">Namespace</th>\n')
    _print(1, '<th scope="col">Capability</th>\n')
    _print(2, '</tr>\n')
    _print(3, '</thead>\n')
    _print(3, '<tbody>\n')
    for namespaces, capabilities in obj.get("CAPABILITY", {}).items():
        _print(4, '<tr>\n')
        _print(4, '<th width="25%" scope="row">'+namespaces+'</th>\n')
        _print(4, '<td>\n')
        for capability in capabilities:
            _print(5, '<li>'+capability+'</li>\n')
        _print(4, '</td>\n')
        _print(3, '</tr>\n')
    _print(2, '</tbody>\n')
    _print(1, '</table>\n')

    return mark_safe(result.getvalue())


@register.filter(name="flare_capa_attck")
def flare_capa_attck(obj, *args, **kwargs):
    result = StringIO()
    def _print(lvl, s):
        result.write((lvl * u'  ') + s)

    _print(1, '<table class="table table-striped table-hover table-bordered">\n')
    _print(1, '<thead>\n')
    _print(1, '<tr>\n')
    _print(1, '<th scope="col">ATT&CK Tactic</th>\n')
    _print(1, '<th scope="col">ATT&CK Technique</th>\n')
    _print(2, '</tr>\n')
    _print(3, '</thead>\n')
    _print(3, '<tbody>\n')
    for tactic, techniques in obj.get("ATTCK", {}).items():
        _print(4, '<tr>\n')
        _print(4, '<th scope="row">'+tactic+'</th>\n')
        _print(4, '<td>\n')
        for technique in techniques:
            _print(5, '<li>'+technique+'</li>\n')

        _print(4, '</td>\n')
        _print(3, '</tr>\n')
    _print(2, '</tbody>\n')
    _print(1, '</table>\n')

    return mark_safe(result.getvalue())

@register.filter(name="flare_capa_mbc")
def flare_capa_mbc(obj, *args, **kwargs):
    result = StringIO()
    def _print(lvl, s):
        result.write((lvl * u'  ') + s)

    _print(1, '<table class="table table-striped table-hover table-bordered">\n')
    _print(1, '<thead>\n')
    _print(1, '<tr>\n')
    _print(1, '<th scope="col">MBC Objective</th>\n')
    _print(1, '<th scope="col">MBC Behavior</th>\n')
    _print(2, '</tr>\n')
    _print(3, '</thead>\n')
    _print(3, '<tbody>\n')
    for objective, behaviors in obj.get("MBC", {}).items():
        _print(4, '<tr>\n')
        _print(4, '<th scope="row">'+objective+'</th>\n')
        _print(4, '<td>\n')
        for behavior in behaviors:
            _print(5, '<li>'+behavior+'</li>\n')

        _print(4, '</td>\n')
        _print(3, '</tr>\n')
    _print(2, '</tbody>\n')
    _print(1, '</table>\n')

    return mark_safe(result.getvalue())

# Thanks Sandor
@register.simple_tag
def malware_config(obj, *args, **kwargs):
    """Custom Django tag for improved malware config rendering.
    This tag will render Python dicts as tables, and Python lists as
    unordered lists. Empty dicts and lists are rendered as empty fields.
    Single element lists are expanded and rendered as regular values.
    """
    level = kwargs.get('level') or 0
    result = StringIO()

    def _print(lvl, s):
        result.write((lvl * u'  ') + str(s))

    if isinstance(obj, dict):
        if obj:
            _print(0, '\n')
            _print(level + 0, '<table>\n')
            for key, val in obj.items():
                _print(level + 1, '<tr>\n')
                _print(level + 2, '<td>' + malware_config(key, level=level + 3) + '</td>\n')
                _print(level + 2, '<td>' + malware_config(val, level=level + 3) + '</td>\n')
                _print(level + 1, '</tr>\n')
            _print(level + 0, '</table>\n')
            _print(level - 1, '')
    elif isinstance(obj, list):
        if obj:
            if len(obj) > 1:
                _print(0, '\n')
                _print(level + 0, '<ul style="columns: 4;">\n')
                for item in obj:
                    _print(level + 1, '<li>' + malware_config(item, level=level + 2) + '</li>\n')
                _print(level + 0, '</ul>\n')
                _print(level - 1, '')
            else:
                result.write(malware_config(obj[0]))
    else:
        result.write(escape(str(obj)))

    return mark_safe(result.getvalue())
