def extract_config(data):
    config_dict = {}
    try:
        lines = data.decode().split("\n")
    except Exception:
        return
    config_dict["Host"] = lines[0]
    config_dict["Port"] = lines[1]
    config_dict["Key"] = lines[2]
    config_dict["SPL"] = lines[3]
    config_dict["USBNM"] = lines[4]
    return config_dict
