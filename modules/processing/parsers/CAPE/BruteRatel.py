from contextlib import suppress


def extract_config(data):
    config_dict = {}

    with suppress(Exception):
        i = 0
        lines = data.decode().split("\n")
        for line in lines:
            if line.startswith("Mozilla"):
                config_dict["User Agent"] = line
                config_dict["C2"] = list(set(lines[i - 2].split(",")))
                config_dict["Port"] = lines[i - 1]
                config_dict["URI"] = lines[i + 3].split(",")
                config_dict["Keys"] = [lines[i + 1], lines[i + 2]]
                break
            i += 1

    return config_dict


if __name__ == "__main__":
    import sys
    from pathlib import Path

    filedata = Path(sys.argv[1]).read_bytes()
    print(extract_config(filedata))
