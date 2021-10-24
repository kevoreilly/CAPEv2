import logging
from Crypto.Cipher import ARC4
from ipaddress import ip_address

log = logging.getLogger(__name__)


def _chunk_stuff(stuff, group_size=20):
    # really just need to chunk out the ip into groups of....20?
    # https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks
    for i in range(0, len(stuff), group_size):
        yield ','.join(stuff[i:i + group_size])


def _build_rc4_rule(passphrase):
    hex_plain_text = "5b4461746153746172745d00000000"

    cipher = ARC4.new(passphrase)
    value = bytes.fromhex(hex_plain_text)
    enc_value = cipher.encrypt(value)

    # conver the encrypted form if the plain text to a hex string
    enc_hex_value = enc_value.hex()

    first_value = ""
    second_value = ""
    # split the first part into two char groups as hex, we need these for the rules
    # skip over the last 8 bytes
    for i in range(0, len(enc_hex_value) - 8, 2):
        first_value += f"{enc_hex_value[i:i + 2]} "

    # only take the last 4 bytes
    for i in range(len(enc_hex_value) - 4, len(enc_hex_value), 2):
        second_value += f"{enc_hex_value[i:i + 2]} "

    return first_value.rstrip(), second_value.rstrip()


def _parse_mwcp(remcos_config):
    remcos_config_list = []
    control = remcos_config.get('control', [])
    for c in control:
        if c and c.startswith("tcp://"):
            # maxsplit here incase the passphrase includes :
            tmp = c.replace("tcp://", "").split(":", maxsplit=2)
            if tmp:
                # if we don't have a password, just add a blank one,
                if len(tmp) == 2:
                    remcos_config_list.append(
                        {"Version": remcos_config.get("version", ""), "C2": tmp[0], "Port": tmp[1], "Password": ""}
                    )
                elif len(tmp) == 3 and tmp[2] != "":
                    # we can include the passprhase
                    remcos_config_list.append(
                        {"Version": remcos_config.get("version", ""), "C2": tmp[0], "Port": tmp[1], "Password": tmp[2]}
                    )
                else:
                    log.debug(f"[CENTS - Remcos] MWCP config - found to be invalid --> {c}")

    return remcos_config_list


def _parse_ratdecoders(remcos_config):
    domains = remcos_config.get("domains", [])
    remcos_config_list = []
    for domain in domains:
        # why is this a list of lists
        for nested_domain in domain:
            remcos_config_list.append(
                # notice the typo here including the colon after c2:
                # https://github.com/kevthehermit/RATDecoders/blob/master/malwareconfig/decoders/remcos.py#L56
                {"C2": nested_domain.get("c2:", ""),
                 "Port": nested_domain.get("port", ""),
                 "Password": nested_domain.get("password", ""),
                 }
            )

    return remcos_config_list


def cents_remcos(config_dict, sid_counter, md5, date, task_link):
    """Creates Suricata rules from extracted Remcos malware configuration.

    :param config_dict: Dictionary with the extracted Remcos configuration.
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
    # build out an array to store the parsed configs
    remcos_config_list = []

    # lowercase the key names in the configs for constancy
    remcos_config = dict((k.lower(), v) for k, v in config_dict.items())

    if not remcos_config:
        return []

    # there are two remcos parsers that could be at work here
    # 1) RATDecoders - https://github.com/kevthehermit/RATDecoders/blob/master/malwareconfig/decoders/remcos.py
    #    which is an optional configuration that can be enabled in the processing.conf file
    # 2) MWCP - https://github.com/kevoreilly/CAPEv2/blob/master/modules/processing/parsers/mwcp/Remcos.py
    #    which is an optional configuration that can be enabled in the processing.conf file
    if 'control' in remcos_config and 'domains' not in remcos_config:
        # we have an MWCP config
        log.debug("[CENTS - Remcos] Parsing DC3-MWCP based config")
        parsed_remcos_config = _parse_mwcp(remcos_config)
        for _config in parsed_remcos_config:
            if _config not in remcos_config_list:
                remcos_config_list.append(_config)

    if 'domains' in remcos_config and 'control' not in remcos_config:
        # we have a RATDecoders config
        log.debug("[CENTS - Remcos] Parsing RATDecoders based config")
        parsed_remcos_config = _parse_ratdecoders(remcos_config)
        for _config in parsed_remcos_config:
            if _config not in remcos_config_list:
                remcos_config_list.append(_config)

    # if we don't have a parsed config, drop out
    log.debug("[CENTS - Remcos] Done Parsing Config")
    if not remcos_config_list:
        log.debug("[CENTS - Remcos] No parsed configs found")
        return []

    # Now we want to create Suricata rules finally
    rule_list = []
    ip_list = set()
    domain_list = set()
    for c2_server in list(map(lambda x: x.get('C2'), remcos_config_list)):
        try:
            c2_ip = ip_address(c2_server)
        except ValueError:
            domain_list.add(c2_server)
        else:
            # only create rules for "global" ip addresses
            if c2_ip.is_global:
                ip_list.add(c2_server)
            else:
                log.debug("[CENTS - Remcos] Skipping c2 server due to non-routable ip")

    log.debug("[CENTS - Remcos] Building IP based rules")
    for ip_group in _chunk_stuff(list(ip_list)):
        rule = f"alert tcp $HOME_NET any -> {ip_group} any (msg:\"ET CENTS Remcos RAT (C2 IP Address) " \
               f"C2 Communication - CAPE sandbox config extraction\"; flow:established,to_server; " \
               f"reference:md5,{md5}; reference:url,{task_link}; sid:{next_sid}; rev:1; " \
               f"metadata:created_at {date};)"
        rule_list.append(rule)
        next_sid += 1

    log.debug("[CENTS - Remcos] Building Domain based rules")
    for c2_domain in domain_list:
        rule = f"alert dns $HOME_NET any -> any any (msg:\"ET CENTS Remcos RAT (C2 Domain) " \
               f"C2 Communication - CAPE sandbox config extraction\"; flow:established,to_server; " \
               f"dns.query; content:\"{c2_domain}\"; " \
               f"reference:md5,{md5}; reference:url,{task_link}; sid:{next_sid}; rev:1; " \
               f"metadata:created_at {date};)"
        rule_list.append(rule)
        next_sid += 1

    log.debug("[CENTS - Remcos] Building Password based rules")
    for parsed_config in remcos_config_list:
        # if we have a password, we should create a rule for the RC4 encrypted stuff
        if parsed_config.get("Password", ""):
            first, second = _build_rc4_rule(parsed_config.get('Password'))
            rule = f"alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET CENTS Remcos RAT " \
                   f"(passphrase {parsed_config.get('Password')}) " \
                   f"C2 Communication - CAPE sandbox config extraction\"; flow:established,to_server; " \
                   f"content:\"|{first}|\"; startswith; fast_pattern; content:\"|{second}|\"; distance:2; within:2; " \
                   f"reference:md5,{md5}; reference:url,{task_link}; sid:{next_sid}; rev:1; " \
                   f"metadata:created_at {date};)"
            rule_list.append(rule)
            next_sid += 1

    log.debug("[CENTS - Remcos] Returning built rules")
    return rule_list
