def extract_config(data):
    config_parts = data.split("abccba")
    if len(config_parts) <= 5:
        return None
    config_dict = {
        "Domain": config_parts[1],
        "Port": config_parts[2],
        "Campaign Name": config_parts[3],
        "Copy StartUp": config_parts[4],
        "Unknown": config_parts[5],
        "Add To Registry": config_parts[6],
        "Registry Key": config_parts[7],
        "Password": config_parts[8],
        "Anti Kill Process": config_parts[9],
        "USB Spread": config_parts[10],
        "Anti VMWare VirtualBox": config_parts[11],
        "Kill Sandboxie": config_parts[12],
        "Kill WireShark / Apate DNS": config_parts[13],
        "Kill NO-IP": config_parts[14],
        "Block Virus Total": config_parts[15],
        "Install Name": config_parts[16],
        "ByPass Malware Bytes": config_parts[20],
        "Kill SpyTheSPy": config_parts[21],
        "Connection Delay": config_parts[22],
        "Copy To All Drives": config_parts[23],
        "HideProcess": config_parts[24],
    }

    if config_parts[17] == "True":
        config_dict["Install Path"] = "App Data"
    if config_parts[18] == "True":
        config_dict["Install Path"] = "TEMP"
    if config_parts[19] == "True":
        config_dict["Install Path"] = "Documents"
    return config_dict
