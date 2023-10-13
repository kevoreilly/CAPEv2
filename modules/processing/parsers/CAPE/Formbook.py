def extract_config(data):
    config_dict = {}
    i = 0
    try:
        lines = data.decode().split("\n")
    except Exception:
        return
    if lines[0].startswith("POST"):
        while lines[i] != "dat=":
            i += 1
        if lines[i] == "dat=":
            i += 1
    elif "www." not in lines[0]:
        return
    config_dict["C2"] = lines[i]
    decoys = []
    i += 1
    while len(lines[i]) > 0:
        decoys.append(lines[i])
        i += 1
    config_dict["Decoys"] = decoys
    return config_dict
