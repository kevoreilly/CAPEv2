import logging

log = logging.getLogger(__name__)


def cents_cobaltstrikebeacon(config_dict, sid_counter, md5, date):
    """Creates Suricata rules from extracted CobaltStrikeBeacon malware configuration.

    :param config_dict: Dictionary with the extracted CobaltStrikeBeacon configuration.
    :type config_dict: `dict`

    :param sid_counter: Signature ID of the next Suricata rule.
    :type sid_counter: `int`

    :param md5: MD5 hash of the source sample.
    :type md5: `int`

    :param date: Timestamp of the analysis run of the source sample.
    :type date: `str`

    :return List of Suricata rules (`str`) or empty list if no rule has been created.
    """
    if not config_dict or not sid_counter or not md5 or not date:
        return []

    next_sid = sid_counter
    rule_list = []
    try:
        beacon_type = config_dict.get("BeaconType", [])[0]
        port = config_dict.get("Port", [])[0]
        c2 = config_dict.get("C2Server", [])[0].split(",")[0]
    except Exception as e:
        log.warning(f"[CENTS] Exception while trying to create CobaltStrike rules: {e}")

    if beacon_type and port and c2:
        # TODO make this better and differentiate between HTTP and HTTPS beacon types
        rule = f"alert http $HOME_NET any -> $EXTERNAL_NET {port} (msg:\"ET MALWARE CobaltStrike Beacon " \
               f"C2 Communication - CAPE sandbox config extraction\"; flow:established,to_server; " \
               f"content:\"{c2}\"; fast_pattern; reference:md5,{md5}; sid:{next_sid}; rev:1; " \
               f"metadata:created_at {date};)"
        next_sid += 1
        rule_list.append(rule)

    return rule_list
