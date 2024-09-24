from contextlib import suppress

from lib.cuckoo.common.integrations.strings import extract_strings


def extract_config(data):
    config_dict = {}
    with suppress(Exception):
        if data[:2] == b"MZ":
            lines = extract_strings(data=data, on_demand=True, minchars=3)
            if not lines:
                return
        else:
            lines = data.decode().split("\n")
        base = next(i for i, line in enumerate(lines) if "Mozilla/5.0" in line)
        if not base:
            return
        for x in range(1, 32):
            # Data Exfiltration via Telegram
            if "api.telegram.org" in lines[base + x]:
                config_dict["Protocol"] = "Telegram"
                config_dict["C2"] = lines[base + x]
                config_dict["Password"] = lines[base + x + 1]
                break
            # Data Exfiltration via Discord
            elif "discord" in lines[base + x]:
                config_dict["Protocol"] = "Discord"
                config_dict["C2"] = lines[base + x]
                break
            # Data Exfiltration via FTP
            elif "ftp:" in lines[base + x]:
                config_dict["Protocol"] = "FTP"
                config_dict["C2"] = lines[base + x]
                config_dict["Username"] = lines[base + x + 1]
                config_dict["Password"] = lines[base + x + 2]
                break
            # Data Exfiltration via SMTP
            elif "@" in lines[base + x]:
                config_dict["Protocol"] = "SMTP"
                if lines[base + x - 2].isdigit() and len(lines[base + x - 2]) <= 5:  # check if length <= highest Port 65535
                    # minchars 3 so Ports < 100 do not appear in strings / TBD: michars < 3
                    config_dict["Port"] = lines[base + x - 2]
                elif lines[base + x - 2] in {"true", "false"} and lines[base + x - 3].isdigit() and len(lines[base + x - 3]) <= 5:
                    config_dict["Port"] = lines[base + x - 3]
                config_dict["C2"] = lines[base + +x - 1]
                config_dict["Username"] = lines[base + x]
                config_dict["Password"] = lines[base + x + 1]
                if "@" in lines[base + x + 2]:
                    config_dict["EmailTo"] = lines[base + x + 2]
                break
        # Get Persistence Payload Filename
        for x in range(2, 22):
            if ".exe" in lines[base + x]:
                config_dict["Persistence_Filename"] = lines[base + x]
                break
        # Get External IP Check Services
        externalipcheckservices = []
        for x in range(-4, 19):
            if "ipify.org" in lines[base + x] or "ip-api.com" in lines[base + x]:
                externalipcheckservices.append(lines[base + x])
        if externalipcheckservices:
            config_dict["ExternalIPCheckServices"] = externalipcheckservices

        # Data Exfiltration via HTTP(S)
        temp_match = ["http://", "https://"]  # TBD: replace with a better url validator (Regex)
        if "Protocol" not in config_dict.keys():
            for index, string in enumerate(lines[base:]):
                if string == "Win32_BaseBoard":
                    for x in range(1, 8):
                        if any(s in lines[base + index + x] for s in temp_match):
                            config_dict["Protocol"] = "HTTP(S)"
                            config_dict["C2"] = lines[base + index + x]
                            break
        return config_dict
