import os
from io import StringIO

try:
    import re2 as re
except ImportError:
    import re

from collections import OrderedDict
from uuid import NAMESPACE_DNS, uuid3

from django.template.defaultfilters import register
from django.utils.html import escape
from django.utils.safestring import mark_safe


@register.filter("is_string")
def is_string(value):
    return isinstance(value, str)


@register.filter("comma_join")
def comma_join(value):
    return ",".join(str(task) for task in value)


@register.filter("network_rn")
def network_rn_func(value):
    """get basename from path"""
    if isinstance(value, bytes):
        value = value.decode()
    return list(filter(None, value.split("\r\n")))


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
            return str(value.get("_id", ""))
        return ""

    # Return value
    return str(value)


@register.filter("is_dict")
def is_dict(value):
    """Checks if value is an instance of dict"""
    return isinstance(value, dict)


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key, "")


malware_name_url_pattern = """<a href="/analysis/search/detections:{malware_name}"><span style="font-weight: bold;">{malware_name}</span></a>"""


@register.filter("get_detection_by_pid")
def get_detection_by_pid(dictionary, key):
    if not dictionary:
        return
    detections = dictionary.get(str(key), "")
    if detections:
        if len(detections) > 1:
            output = " -> ".join([malware_name_url_pattern.format(malware_name=name) for name in detections])
        else:
            output = malware_name_url_pattern.format(malware_name=detections[0])

        return mark_safe(output)


@register.filter(name="dehex")
def dehex(value):
    return re.sub(r"\\x[0-9a-f]{2}", "", value)


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
        result.write((lvl * "  ") + s)

    _print(1, '<table class="table table-striped table-hover table-bordered">\n')
    _print(1, "<thead>\n")
    _print(1, "<tr>\n")
    _print(1, '<th scope="col">Namespace</th>\n')
    _print(1, '<th scope="col">Capability</th>\n')
    _print(2, "</tr>\n")
    _print(3, "</thead>\n")
    _print(3, "<tbody>\n")
    for namespaces, capabilities in obj.get("CAPABILITY", {}).items():
        _print(4, "<tr>\n")
        _print(4, '<th width="25%" scope="row">' + namespaces + "</th>\n")
        _print(4, "<td>\n")
        for capability in capabilities:
            _print(5, "<li>" + capability + "</li>\n")
        _print(4, "</td>\n")
        _print(3, "</tr>\n")
    _print(2, "</tbody>\n")
    _print(1, "</table>\n")

    ret_result = result.getvalue()
    result.close()
    return mark_safe(ret_result)


@register.filter(name="flare_capa_attck")
def flare_capa_attck(obj, *args, **kwargs):
    result = StringIO()

    def _print(lvl, s):
        result.write((lvl * "  ") + s)

    _print(1, '<table class="table table-striped table-hover table-bordered">\n')
    _print(1, "<thead>\n")
    _print(1, "<tr>\n")
    _print(1, '<th scope="col">ATT&CK Tactic</th>\n')
    _print(1, '<th scope="col">ATT&CK Technique</th>\n')
    _print(2, "</tr>\n")
    _print(3, "</thead>\n")
    _print(3, "<tbody>\n")
    for tactic, techniques in obj.get("ATTCK", {}).items():
        _print(4, "<tr>\n")
        _print(4, '<th width="25%" scope="row">' + tactic + "</th>\n")
        _print(4, "<td>\n")
        for technique in techniques:
            _print(5, "<li>" + technique + "</li>\n")

        _print(4, "</td>\n")
        _print(3, "</tr>\n")
    _print(2, "</tbody>\n")
    _print(1, "</table>\n")

    ret_result = result.getvalue()
    result.close()
    return mark_safe(ret_result)


@register.filter(name="flare_capa_mbc")
def flare_capa_mbc(obj, *args, **kwargs):
    result = StringIO()

    def _print(lvl, s):
        result.write((lvl * "  ") + s)

    _print(1, '<table class="table table-striped table-hover table-bordered">\n')
    _print(1, "<thead>\n")
    _print(1, "<tr>\n")
    _print(1, '<th scope="col">MBC Objective</th>\n')
    _print(1, '<th scope="col">MBC Behavior</th>\n')
    _print(2, "</tr>\n")
    _print(3, "</thead>\n")
    _print(3, "<tbody>\n")
    for objective, behaviors in obj.get("MBC", {}).items():
        _print(4, "<tr>\n")
        _print(4, '<th width="25%" scope="row">' + objective + "</th>\n")
        _print(4, "<td>\n")
        for behavior in behaviors:
            _print(5, "<li>" + behavior + "</li>\n")

        _print(4, "</td>\n")
        _print(3, "</tr>\n")
    _print(2, "</tbody>\n")
    _print(1, "</table>\n")

    ret_result = result.getvalue()
    result.close()
    return mark_safe(ret_result)


# Thanks Sandor
@register.simple_tag
def malware_config(obj, *args, **kwargs):
    """Custom Django tag for improved malware config rendering.
    This tag will render Python dicts as tables, and Python lists as
    unordered lists. Empty dicts and lists are rendered as empty fields.
    Single element lists are expanded and rendered as regular values.
    """
    level = kwargs.get("level") or 0
    result = StringIO()

    def _print(lvl, s):
        result.write((lvl * "  ") + str(s))

    if isinstance(obj, dict):
        if obj:
            _print(0, "\n")
            _print(level + 0, "<table>\n")
            for key, val in obj.items():
                _print(level + 1, "<tr>\n")
                _print(level + 2, "<td>" + malware_config(key, level=level + 3) + "</td>\n")
                _print(level + 2, "<td>" + malware_config(val, level=level + 3) + "</td>\n")
                _print(level + 1, "</tr>\n")
            _print(level + 0, "</table>\n")
            _print(level - 1, "")
    elif isinstance(obj, list):
        if obj:
            if len(obj) > 1:
                _print(0, "\n")
                _print(level + 0, '<ul style="margin: 0;columns: 4;">\n')
                for item in obj:
                    _print(level + 1, "<li>" + malware_config(item, level=level + 2) + "</li>\n")
                _print(level + 0, "</ul>\n")
                _print(level - 1, "")
            else:
                result.write(malware_config(obj[0]))
    else:
        result.write(escape(str(obj)))

    ret_result = result.getvalue()
    result.close()
    return mark_safe(ret_result)


@register.filter(name="playback_url")
def playback_url(task_id):
    session_id = uuid3(NAMESPACE_DNS, str(task_id)).hex[:16]
    return f"{task_id}_{session_id}"


@register.filter
def split_csv(value):
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [t.strip() for t in str(value).split(",") if t.strip()]

@register.filter
def cert_chain_signers(signers):
    return [s for s in (signers or []) if "Certificate Chain" in s.get("name", "")]


@register.filter
def ts_chain_signers(signers):
    return [s for s in (signers or []) if "Timestamp Chain" in s.get("name", "")]


_SERVICE_SVGS = {
    "vt": (
        '<svg class="ext-svc-svg" viewBox="0 0 24 24" aria-hidden="true">'
        '<path fill="currentColor" d="M2.5 4h19l-8.2 8 8.2 8h-19l8.2-8-8.2-8zm4.7 2.5L13 12l-5.8 5.5h9.6L11.2 12l5.6-5.5H7.2z"/>'
        "</svg>"
    ),
    "tf": (
        '<svg class="ext-svc-svg" viewBox="0 0 24 24" aria-hidden="true">'
        '<path fill="currentColor" d="M4 3l5.5 4.2h5L20 3l-1.5 9.2L12 21l-6.5-8.8L4 3zm4.8 7.5a1.3 1.3 0 1 0 0 2.6 1.3 1.3 0 0 0 0-2.6zm6.4 0a1.3 1.3 0 1 0 0 2.6 1.3 1.3 0 0 0 0-2.6zM12 15.2l-2 1.8h4l-2-1.8z"/>'
        "</svg>"
    ),
    "et": (
        '<svg class="ext-svc-svg" viewBox="0 0 24 24" aria-hidden="true">'
        '<path fill="currentColor" d="M12 2L4 5.5v6.1c0 5.3 3.4 10.2 8 11.4 4.6-1.2 8-6.1 8-11.4V5.5L12 2zm0 3.2a5.8 5.8 0 1 1 0 11.6 5.8 5.8 0 0 1 0-11.6zm0 2.2a3.6 3.6 0 1 0 0 7.2 3.6 3.6 0 0 0 0-7.2zm0 2.1a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3z"/>'
        "</svg>"
    ),
    "pt": (
        '<svg class="ext-svc-svg" viewBox="0 0 24 24" aria-hidden="true">'
        '<path fill="currentColor" d="M6 4a3 3 0 1 0 2.1 5.1l2.5 2.5a3.1 3.1 0 0 0 0 1.8l-2.5 2.5A3 3 0 1 0 9 18c0-.5-.1-.9-.3-1.3l2.5-2.5a3 3 0 0 0 2.6 0l2.5 2.5A3 3 0 1 0 18 15c-.8 0-1.5.3-2.1.9l-2.5-2.5a3.1 3.1 0 0 0 0-1.8l2.5-2.5A3 3 0 1 0 15 6c0 .5.1.9.3 1.3l-2.5 2.5a3 3 0 0 0-2.6 0L7.7 7.3C7.9 6.9 8 6.5 8 6a3 3 0 0 0-2-2z"/>'
        "</svg>"
    ),
    "mwdb": (
        '<svg class="ext-svc-svg" viewBox="0 0 24 24" aria-hidden="true">'
        '<path fill="currentColor" d="M12 2L3 7v10l9 5 9-5V7l-9-5zm0 2.3l6.5 3.6L12 11.5 5.5 7.9 12 4.3zm-7 5.4l6 3.4v6.7l-6-3.3V9.7zm8 10.1v-6.7l6-3.4v6.8l-6 3.3z"/>'
        "</svg>"
    ),
    "bazaar": (
        '<svg class="ext-svc-svg" viewBox="0 0 24 24" aria-hidden="true">'
        '<path fill="currentColor" d="M14 6.2V5a2 2 0 0 0-4 0v1.2A5.9 5.9 0 0 0 6.5 10H4v2h2.1c-.1.5-.1 1-.1 1.5V14H4v2h2.3A6 6 0 0 0 18 16h2v-2h-2v-.5c0-.5 0-1-.1-1.5H20v-2h-2.5A5.9 5.9 0 0 0 14 6.2zM10 11h4v2h-4v-2zm0 4h4v2h-4v-2z"/>'
        "</svg>"
    ),
    "malpedia": (
        '<svg class="ext-svc-svg" viewBox="0 0 24 24" aria-hidden="true">'
        '<path fill="currentColor" d="M4 4.5A2.5 2.5 0 0 1 6.5 2H11v17.5a2.5 2.5 0 0 0-2.5-2.5H4V4.5zm16 0A2.5 2.5 0 0 0 17.5 2H13v17.5a2.5 2.5 0 0 1 2.5-2.5H20V4.5zM6.5 19A1.5 1.5 0 0 1 8 20.5h8a1.5 1.5 0 0 1 1.5-1.5H20v2H4v-2h2.5z"/>'
        "</svg>"
    ),
    "mlch": (
        '<svg class="ext-svc-svg" viewBox="0 0 24 24" aria-hidden="true">'
        '<path fill="currentColor" d="M10.5 3a7.5 7.5 0 1 0 4.6 13.4l4.7 4.7 1.4-1.4-4.7-4.7A7.5 7.5 0 0 0 10.5 3zm0 2a5.5 5.5 0 1 1 0 11 5.5 5.5 0 0 1 0-11z"/>'
        "</svg>"
    ),
}

_SERVICE_ALIASES = {
    "virustotal": "vt",
    "threatfox": "tf",
    "emergingthreats": "et",
    "proofpoint": "et",
    "passivetotal": "pt",
    "moloch": "mlch",
    "arkime": "mlch",
    "malwarebazaar": "bazaar",
    "malpedia_actors": "malpedia",
}

_SERVICE_TITLES = {
    "vt": "Lookup on VirusTotal",
    "tf": "View indicator on ThreatFox",
    "et": "Search on Proofpoint Emerging Threats",
    "pt": "Lookup on PassiveTotal",
    "mwdb": "Lookup on CERT.PL MWDB",
    "bazaar": "Lookup on abuse.ch MalwareBazaar",
    "malpedia": "View on Malpedia",
    "mlch": "View in Arkime / Moloch",
}


def _resolve_service_key(service: str) -> str:
    s = (service or "").strip().lower()
    return _SERVICE_ALIASES.get(s, s)


@register.simple_tag
def ext_service_icon(service: str):
    key = _resolve_service_key(service)
    svg = _SERVICE_SVGS.get(key)
    if not svg:
        svg = '<i class="fas fa-external-link-alt ext-svc-svg" aria-hidden="true"></i>'
    return mark_safe(svg)


@register.simple_tag
def ext_service_link(service: str, url: str, title: str = "", label: str = ""):
    if not url:
        return ""
    key = _resolve_service_key(service)
    svg = _SERVICE_SVGS.get(key, '<i class="fas fa-external-link-alt ext-svc-svg" aria-hidden="true"></i>')
    resolved_title = escape(title or _SERVICE_TITLES.get(key, f"View on {service}"))
    safe_url = escape(str(url))
    label_html = f'<span class="ext-svc-label">{escape(label)}</span>' if label else ""
    return mark_safe(
        f'<a href="{safe_url}" target="_blank" rel="noopener" '
        f'class="ext-svc-btn ext-svc-{escape(key)}" title="{resolved_title}" aria-label="{resolved_title}">'
        f"{svg}{label_html}</a>"
    )


@register.simple_tag
def ext_lookup(service: str, target, kind: str = "ip", label: str = "", title: str = ""):
    if target is None or target == "":
        return ""
    key = _resolve_service_key(service)
    t = str(target).strip()
    if not t:
        return ""
    if key == "vt":
        if kind == "domain":
            url = f"https://www.virustotal.com/gui/domain/{t}/detection"
        elif kind == "file":
            url = f"https://www.virustotal.com/gui/file/{t}/"
        else:
            url = f"https://www.virustotal.com/gui/ip-address/{t}/detection"
    elif key == "et":
        url = f"https://threatintel.proofpoint.com/search?q={t}"
    elif key == "pt":
        url = f"https://www.passivetotal.org/passive/{t}"
    elif key == "mwdb":
        url = f"https://mwdb.cert.pl/file/{t}"
    elif key == "bazaar":
        url = f"https://bazaar.abuse.ch/sample/{t}/"
    elif key == "mlch":
        url = t
    else:
        url = t
    return ext_service_link(key, url, title=title, label=label)


@register.simple_tag
def threatintel_badges(hits):
    if not hits or not isinstance(hits, (list, tuple)):
        return ""
    parts = ['<span class="ti-badges-wrap ms-1">']
    for ti in hits:
        if not isinstance(ti, dict):
            continue
        tag = escape(str(ti.get("tag") or ""))
        if not tag:
            continue
        tooltip = escape(str(ti.get("tooltip") or ""))
        ind_url = ti.get("indicator_url")
        source = _resolve_service_key(str(ti.get("source") or "tf"))
        source_label = "ThreatFox" if source == "tf" else str(ti.get("source") or "Threat Intel").capitalize()
        parts.append('<span class="ti-pill">')
        parts.append(f'<span class="ti-pill-tag" title="{tooltip}">{tag}</span>')
        if ind_url:
            svg = _SERVICE_SVGS.get(source, _SERVICE_SVGS["tf"])
            link_title = escape(f"View indicator on {source_label}" + (f" ({ti.get('tooltip')})" if ti.get("tooltip") else ""))
            parts.append(
                f'<a href="{escape(str(ind_url))}" target="_blank" rel="noopener" '
                f'class="ti-pill-link ext-svc-{escape(source)}" title="{link_title}" aria-label="{link_title}">'
                f"{svg}</a>"
            )
        parts.append("</span>")
    parts.append("</span>")
    return mark_safe("".join(parts))
