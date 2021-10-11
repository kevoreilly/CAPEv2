import logging

log = logging.getLogger(__name__)


def cents_remcos(config_dict, sid_counter, md5):
    """Creates Suricata rules from extracted Remcos malware configuration.

    :param config_dict: Dictionary with the extracted Remcos configuration.
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
    # not all configs look the same
    remcos_config_list = []
    remcos_config = dict((k.lower(), v) for k, v in config_dict.items())
    if remcos_config:
        version = remcos_config.get("version", "")
        control = remcos_config.get("control", [])
        domains = remcos_config.get("domains", [])
        if not version:
            log.debug("[CENTS] Remcos config found without version")
            return []

        else:
            if control:
                for c in control:
                    if c and c.startswith("tcp://"):
                        tmp = c.replace("tcp://", "").split(":")
                        if tmp and len(tmp) == 2:
                            remcos_config_list.append(
                                {
                                    "Version": version[0],
                                    "C2": tmp[0],
                                    "Port": tmp[1],
                                }
                            )
            if domains:
                for d1 in domains:
                    for d2 in d1:
                        c2 = d2.get("c2:", "")
                        port = d2.get("port", "")
                        if c2 and port:
                            remcos_config_list.append(
                                {
                                    "Version": version[0],
                                    "C2": c2,
                                    "Port": port,
                                }
                            )

    if not remcos_config_list:
        return []

    # Now we want to create Suricata rules finally
    rule_list = []
    for obj in remcos_config_list:
        version = obj.get("Version")
        c2 = obj.get("C2")
        port = obj.get("Port")
        rule = f"alert tcp $HOME_NET any -> $EXTERNAL_NET {port} (msg:\"ET MALWARE Remcos RAT (Version {version}) " \
               f"C2 Communication - CAPE sandbox config extraction\"; flow:established,to_server; " \
               f"content:\"{c2}\"; fast_pattern; reference:md5,{md5}; sid:{next_sid}; rev:1;)"
        next_sid += 1
        rule_list.append(rule)
    return rule_list
