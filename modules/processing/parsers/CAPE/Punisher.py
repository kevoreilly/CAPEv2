import os


def extract_config(data):
    config = {}
    config_parts = data.split("abccba".encode())
    if len(config_parts) <= 5:
        return None

    config['tcp'] = [{'server_domain': config_parts[1].decode(), 'server_port': config_parts[2].decode()}]
    config['campaign_id'] = [config_parts[3].decode()]
    config['password'] = [config_parts[8].decode()]
    config['registry'] = [{'key': config_parts[7].decode()}]
    config['decoded_strings'] = [config_parts[5].decode()]
    config['sleep_delay'] = config_parts[22]

    install_name = config_parts[16]
    config_dict = {
        "Copy StartUp": config_parts[4],
        "Add To Registry": config_parts[6],
        "Anti Kill Process": config_parts[9],
        "USB Spread": config_parts[10],
        "Anti VMWare VirtualBox": config_parts[11],
        "Kill Sandboxie": config_parts[12],
        "Kill WireShark / Apate DNS": config_parts[13],
        "Kill NO-IP": config_parts[14],
        "Block Virus Total": config_parts[15],
        "ByPass Malware Bytes": config_parts[20],
        "Kill SpyTheSPy": config_parts[21],
        "Copy To All Drives": config_parts[23],
        "HideProcess": config_parts[24],
    }
    for capability, status in config_dict.items():
        key = "capability_enabled" if status == b'1' else "capability_disabled"
        config.setdefault(key, []).append(capability)

    install_path = ""
    if config_parts[17] == b"True":
        install_path = "App Data"
    if config_parts[18] == b"True":
        install_path = "TEMP"
    if config_parts[19] == b"True":
        install_path = "Documents"

    config['paths'] = [{'path': os.path.join(install_path, install_name), 'usage': 'install'}]

    return config
