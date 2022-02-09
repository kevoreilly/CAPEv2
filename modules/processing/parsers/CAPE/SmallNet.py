def ver_52(data):
    config_parts = data.split("!!<3SAFIA<3!!")
    config_dict = {
        "Domain": config_parts[1],
        "Port": config_parts[2],
        "Disbale Registry": config_parts[3],
        "Disbale TaskManager": config_parts[4],
        "Install Server": config_parts[5],
        "Registry Key": config_parts[8],
        "Install Name": config_parts[9],
        "Disbale UAC": config_parts[10],
        "Anti-Sandboxie": config_parts[13],
        "Anti-Anubis": config_parts[14],
        "Anti-VirtualBox": config_parts[15],
        "Anti-VmWare": config_parts[16],
        "Anti-VirtualPC": config_parts[17],
        "ServerID": config_parts[18],
        "USB Spread": config_parts[19],
        "P2P Spread": config_parts[20],
        "RAR Spread": config_parts[21],
        "MSN Spread": config_parts[22],
        "Yahoo Spread": config_parts[23],
        "LAN Spread": config_parts[24],
        "Disbale Firewall": config_parts[25],
        "Delay Execution MiliSeconds": config_parts[26],
        "Attribute Read Only": config_parts[27],
        "Attribute System File": config_parts[28],
        "Attribute Hidden": config_parts[29],
        "Attribute Compressed": config_parts[30],
        "Attribute Temporary": config_parts[31],
        "Attribute Archive": config_parts[32],
        "Modify Creation Date": config_parts[33],
        "Modified Creation Data": config_parts[34],
        "Thread Persistance": config_parts[35],
        "Anti-ZoneAlarm": config_parts[36],
        "Anti-SpyTheSpy": config_parts[37],
        "Anti-NetStat": config_parts[38],
        "Anti-TiGeRFirewall": config_parts[39],
        "Anti-TCPview": config_parts[40],
        "Anti-CurrentPorts": config_parts[41],
        "Anti-RogueKiller": config_parts[42],
        "Enable MessageBox": config_parts[43],
        "MessageBox Message": config_parts[44],
        "MessageBox Icon": config_parts[45],
        "MessageBox Buttons": config_parts[46],
        "MessageBox Title": config_parts[47],
    }

    if config_parts[6] == 1:
        config_dict["Install Path"] = "Temp"
    if config_parts[7] == 1:
        config_dict["Install Path"] = "Windows"
    if config_parts[11] == 1:
        config_dict["Install Path"] = "System32"
    if config_parts[12] == 1:
        config_dict["Install Path"] = "Program Files"
    return config_dict


def ver_5(data):
    config_parts = data.split("!!ElMattadorDz!!")
    config_dict = {
        "Domain": config_parts[1],
        "Port": config_parts[2],
        "Disable Registry": config_parts[3],
        "Disbale TaskManager": config_parts[4],
        "Install Server": config_parts[5],
        "Registry Key": config_parts[8],
        "Install Name": config_parts[9],
        "Disbale UAC": config_parts[10],
        "Anti-Sandboxie": config_parts[13],
        "Anti-Anubis": config_parts[14],
        "Anti-VirtualBox": config_parts[15],
        "Anti-VmWare": config_parts[16],
        "Anti-VirtualPC": config_parts[17],
        "ServerID": config_parts[18],
        "USB Spread": config_parts[19],
        "P2P Spread": config_parts[20],
        "RAR Spread": config_parts[21],
        "MSN Spread": config_parts[22],
        "Yahoo Spread": config_parts[23],
        "LAN Spread": config_parts[24],
        "Disbale Firewall": config_parts[25],
        "Delay Execution MiliSeconds": config_parts[26],
    }

    if config_parts[6] == 1:
        config_dict["Install Path"] = "Temp"
    if config_parts[7] == 1:
        config_dict["Install Path"] = "Windows"
    if config_parts[11] == 1:
        config_dict["Install Path"] = "System32"
    if config_parts[12] == 1:
        config_dict["Install Path"] = "Program Files"
    return [config_dict, [config_dict["Domain"]]]


def extract_config(data):
    if "!!<3SAFIA<3!!" in data:
        return ver_52(data)

    elif "!!ElMattadorDz!!" in data:
        return ver_5(data)
