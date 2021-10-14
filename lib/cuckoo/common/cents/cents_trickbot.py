import logging

log = logging.getLogger(__name__)


def cents_trickbot(config_dict, sid_counter, md5, task_link):
    """Creates Suricata rules from extracted TrickBot malware configuration.

    :param config_dict: Dictionary with the extracted TrickBot configuration.
    :type config_dict: `dict`

    :param sid_counter: Signature ID of the next Suricata rule.
    :type sid_counter: `int`

    :param md5: MD5 hash of the source sample.
    :type md5: `int`

    :param task_link: Link to analysis task of the source sample.
    :type task_link: `str`

    :return List of Suricata rules (`str`) or empty list if no rule has been created.
    """
    if not config_dict or not sid_counter or not md5 or not task_link:
        return []

    next_sid = sid_counter
    rule_list = []
    servs = config_dict.get("servs", [])
    gtag = config_dict.get("gtag", "")
    ver = config_dict.get("ver", "")
    for s in servs:
        ip = s.split(":", 1)[0]
        port = s.split(":", 1)[1]
        rule = f"alert ip $HOME_NET any -> {ip} {port} (msg:\"ET MALWARE TrickBot Beacon (gtag {gtag}, version {ver})" \
               f" C2 Communication - CAPE sandbox config extraction\"; flow:established,to_server; " \
               f"reference:md5,{md5}; reference:url,{task_link}; sid:{next_sid}; rev:1;)"
        next_sid += 1
        rule_list.append(rule)

    return rule_list
