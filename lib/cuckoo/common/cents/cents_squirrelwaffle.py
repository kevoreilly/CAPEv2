import logging

log = logging.getLogger(__name__)


def cents_squirrelwaffle(config_dict, sid_counter, md5):
    """Creates Suricata rules from extracted SquirrelWaffle malware configuration.

    :param config_dict: Dictionary with the extracted SquirrelWaffle configuration.
    :type config_dict: `dict`

    :param sid_counter: Signature ID of the next Suricata rule.
    :type sid_counter: `int`

    :param md5: MD5 hash of the source sample.
    :type md5: `int`

    :return List of Suricata rules (`str`) or empty list if no rule has been created.
    """
    if not config_dict or not sid_counter or not md5:
        return []

    next_sid = sid_counter
    rule_list = []
    url_list = config_dict.get("URLs", [])
    for url in url_list:
        if url.lower().startswith("http"):
            host = url.split("/", 1)[1].rsplit("/", 1)[0].replace("/", "")
            uri = url.split("/", 1)[1].rsplit("/", 1)[1]
        else:
            host = url.split("/", 1)[0]
            uri = "/" + url.split("/", 1)[1]
        rule = f"alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET MALWARE SquirrelWaffle Beacon " \
               f"C2 Communication - CAPE sandbox config extraction\"; flow:established,to_server; " \
               f"http.method; content:\"POST\"; http.host; content:\"{host}\"; fast_pattern; reference:md5,{md5}; " \
               f"http.uri; content:\"{uri}\"; sid:{next_sid}; rev:1;)"
        next_sid += 1
        rule_list.append(rule)

    return rule_list
