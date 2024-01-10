def extract_config(data):
    config_dict = {}
    C2s = []
    try:
        lines = data.decode().split("\n")
        for line in lines:
            if "." in line and len(line) > 2:
                C2s.append(line)
    except Exception:
        return
    config_dict["C2s"] = C2s
    return config_dict
