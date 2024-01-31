def extract_config(data):
    config_dict = {}
    C2s = []
    try:
        domain = ""
        uri = ""
        lines = data.decode().split("\n")
        for line in lines:
            if line.startswith("http") and "://" in line:
                domain = line
            if line.startswith("/") and line[-4] == ".":
                uri = line
        if domain and uri:
            C2s = [f"{domain}{uri}"]
    except Exception:
        return
    config_dict["C2s"] = C2s
    return config_dict
