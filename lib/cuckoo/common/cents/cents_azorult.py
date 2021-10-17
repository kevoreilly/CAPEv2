import logging

log = logging.getLogger(__name__)

def cents_azorult(config_dict, sid_counter, md5, date, task_link):
    """Creates Suricata rules from extracted Azorult malware configuration.

    :param config_dict: Dictionary with the extracted Azorult configuration.
    :type config_dict: `dict`

    :param sid_counter: Signature ID of the next Suricata rule.
    :type sid_counter: `int`

    :param md5: MD5 hash of the source sample.
    :type md5: `int`
    
    :param date: Timestamp of the analysis run of the source sample.
    :type date: `str`

    :param task_link: Link to analysis task of the source sample.
    :type task_link: `str`

    :return List of Suricata rules (`str`) or empty list if no rule has been created.
    """
    if not config_dict or not sid_counter or not md5 or not date or not task_link:
        return []

    next_sid = sid_counter
    rule_list = []
    address_list = config_dict.get("address", [])
    for address in address_list:
        rule = f"alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET MALWARE Azorult Beacon " \
               f"C2 Communication - CAPE sandbox config extraction\"; flow:established,to_server; " \
               f"http.host; content:\"{address}\"; fast_pattern; reference:md5,{md5}; reference:url,{task_link}; " \
               f"sid:{next_sid}; rev:1; metadata:created_at {date};)"
        next_sid += 1
        rule_list.append(rule)

    return rule_list
