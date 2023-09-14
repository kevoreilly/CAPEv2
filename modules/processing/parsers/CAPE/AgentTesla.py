def extract_config(data):
    config_dict = {}
    if data[:2] == b"MZ":
        return
    try:
        lines = data.decode().split("\n")
    except Exception:
        return
    i = 0
    while len(lines[i]) != 1:
        i += 1
    if lines[i] == "1":
        config_dict["Protocol"] = "SMTP"
        config_dict["Port"] = lines[i + 2]
        config_dict["C2"] = lines[i + 4]
        config_dict["Username"] = lines[i + 5]
        config_dict["Password"] = lines[i + 6]
    elif lines[i] == "2":
        config_dict["Protocol"] = "FTP"
        config_dict["C2"] = lines[i + 1]
        config_dict["Username"] = lines[i + 2]
        config_dict["Password"] = lines[i + 3]
    elif lines[i] == "3":
        config_dict["Protocol"] = "Telegram"
        config_dict["C2"] = lines[i + 1]
        config_dict["Password"] = lines[i + 2]
    elif lines[i] == "4":
        config_dict["Protocol"] = "Discord"
        config_dict["C2"] = lines[i + 1]
    else:
        return
    return config_dict
