def extract_config(data):
    config_dict = {}
    C2s = []
    try:
        lines = data.decode().split("\n")
        for line in lines:
            if line.startswith("http") and "://" in line:
                C2s.append(line)
                print(line)
            if line.startswith("/") and line[-4] == ".":
                config_dict["Path"] = line
    except Exception:
        return
    config_dict["C2s"] = C2s
    return config_dict
