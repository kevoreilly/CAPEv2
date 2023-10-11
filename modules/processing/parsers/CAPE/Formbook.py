def extract_config(data):
    config_dict = {}
    if data[:4] != b"POST":
        return
    try:
        lines = data.decode().split("\n")
    except Exception:
        return
    i = 0
    while lines[i] != "dat=":
        i += 1
    if lines[i] == "dat=":
        config_dict["C2"] = lines[i + 1]
        decoys = []
        i += 2
        while len(lines[i]) > 0:
            decoys.append(lines[i])
            i += 1
        config_dict["Decoys"] = decoys
    else:
        return
    return config_dict
