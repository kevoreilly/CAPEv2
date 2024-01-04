from contextlib import suppress

from lib.cuckoo.common.integrations.strings import extract_strings


def extract_config(data):
    config_dict = {}
    if data[:2] == b"MZ":
        lines = extract_strings(data=data, on_demand=True, minchars=3)
        if not lines:
            return
        with suppress(Exception):
            base = next(i for i, line in enumerate(lines) if "Mozilla/5.0" in line)
            if base:
                # Check if string true or false is next string
                if (lines[base + 1] == "false") or (lines[base + 1] == "true"):
                    base = base + 1
                # Data Exfiltration via Telegram
                if "api.telegram.org" in lines[base + 1]:
                    config_dict["Protocol"] = "Telegram"
                    config_dict["C2"] = lines[base + 1]
                    config_dict["Password"] = lines[base + 2]
                # Data Exfiltration via Discord
                elif "discord.com" in lines[base + 1]:
                    config_dict["Protocol"] = "Discord"
                    config_dict["C2"] = lines[base + 1]
                # Data Exfiltration via FTP
                elif "ftp:" in lines[base + 1]:
                    config_dict["Protocol"] = "FTP"
                    config_dict["C2"] = lines[base + 1]
                    config_dict["Username"] = lines[base + 2]
                    config_dict["Password"] = lines[base + 3]
                # Data Exfiltration via SMTP
                elif "@" in lines[base + 3]:
                    config_dict["Protocol"] = "SMTP"
                    config_dict["Port"] = lines[base + 1]
                    config_dict["C2"] = lines[base + 2]
                    config_dict["Username"] = lines[base + 3]
                    config_dict["Password"] = lines[base + 4]
                # Get Payload Filename
                for x in range(1, 10):
                    if ".exe" in lines[base + x]:
                        config_dict["Filename"] = lines[base + x]
                return config_dict
        return
    try:
        lines = data.decode().split("\n")
        i = 0
        while len(lines[i]) != 1:
            i += 1
        while len(lines[i + 1]) == 1:
            i += 1
        while int(lines[i]) > 4:
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
    except Exception:
        return
    return config_dict
