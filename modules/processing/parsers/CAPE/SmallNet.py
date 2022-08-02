from gettext import install
import os


def ver_52(data):
    config_parts = data.split("!!<3SAFIA<3!!")
    config = {
        "family": "SmallNet",
        "category": ["rat"],
        "version": "5.2",
        "tcp": [{
            'server_domain': config_parts[1],
            'server_port': config_parts[2]
        }, {
            'server_domain': config_parts[5],  # Install Server
            'usage': 'c2'
        }],
        'registry': [{
            'key': config_parts[8]
        }],
    }
    config_dict = {
        "Disable Registry": config_parts[3],
        "Disable TaskManager": config_parts[4],
        "Disable UAC": config_parts[10],
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
        "Disable Firewall": config_parts[25],
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

    install_path = config_parts[9]
    if config_parts[6] == 1:
        install_path = os.path.join("Temp", config_parts[9])
    if config_parts[7] == 1:
        install_path = os.path.join("Windows", config_parts[9])
    if config_parts[11] == 1:
        install_path = os.path.join("System32", config_parts[9])
    if config_parts[12] == 1:
        install_path = os.path.join("Program Files", config_parts[9])

    config["paths"] = [{'path': install_path, 'usage': 'install'}]
    config["other"] = config_dict  # Placing in other for now
    return config


def ver_5(data):
    config_parts = data.split("!!ElMattadorDz!!")
    config = {
        "family": "SmallNet",
        "category": ["rat"],
        "version": "5",
        "tcp": [{
            'server_domain': config_parts[1],
            'server_port': config_parts[2]
        }, {
            'server_domain': config_parts[5],  # Install Server
            'usage': 'c2'
        }],
        'registry': [{
            'key': config_parts[8]
        }],
    }
    config_dict = {
        "Disable Registry": config_parts[3],
        "Disable TaskManager": config_parts[4],
        "Disable UAC": config_parts[10],
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
        "Disable Firewall": config_parts[25],
        "Delay Execution MiliSeconds": config_parts[26],
    }

    install_path = config_parts[9]
    if config_parts[6] == 1:
        install_path = os.path.join("Temp", config_parts[9])
    if config_parts[7] == 1:
        install_path = os.path.join("Windows", config_parts[9])
    if config_parts[11] == 1:
        install_path = os.path.join("System32", config_parts[9])
    if config_parts[12] == 1:
        install_path = os.path.join("Program Files", config_parts[9])
    config["paths"] = [{'path': install_path, 'usage': 'install'}]
    config["other"] = config_dict  # Placing in other for now

    return config


def extract_config(data):
    try:
        if isinstance(data, bytes):
            data = data.decode()
    except:
        return

    if "!!<3SAFIA<3!!" in data:
        return ver_52(data)

    elif "!!ElMattadorDz!!" in data:
        return ver_5(data)
