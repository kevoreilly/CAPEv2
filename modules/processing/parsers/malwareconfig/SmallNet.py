def ver_52(data):
    config_dict = {}
    config_parts = data.split('!!<3SAFIA<3!!')
    config_dict['Domain'] = config_parts[1]
    config_dict['Port'] = config_parts[2]
    config_dict['Disbale Registry'] = config_parts[3]
    config_dict['Disbale TaskManager'] = config_parts[4]
    config_dict['Install Server'] = config_parts[5]
    config_dict['Registry Key'] = config_parts[8]
    config_dict['Install Name'] = config_parts[9]
    config_dict['Disbale UAC'] = config_parts[10]
    config_dict['Anti-Sandboxie'] = config_parts[13]
    config_dict['Anti-Anubis'] = config_parts[14]
    config_dict['Anti-VirtualBox'] = config_parts[15]
    config_dict['Anti-VmWare'] = config_parts[16]
    config_dict['Anti-VirtualPC'] = config_parts[17]
    config_dict['ServerID'] = config_parts[18]
    config_dict['USB Spread'] = config_parts[19]
    config_dict['P2P Spread'] = config_parts[20]
    config_dict['RAR Spread'] = config_parts[21]
    config_dict['MSN Spread'] = config_parts[22]
    config_dict['Yahoo Spread'] = config_parts[23]
    config_dict['LAN Spread'] = config_parts[24]
    config_dict['Disbale Firewall'] = config_parts[25] 
    config_dict['Delay Execution MiliSeconds'] = config_parts[26]
    config_dict['Attribute Read Only'] = config_parts[27]
    config_dict['Attribute System File'] = config_parts[28]
    config_dict['Attribute Hidden'] = config_parts[29]
    config_dict['Attribute Compressed'] = config_parts[30]
    config_dict['Attribute Temporary'] = config_parts[31]
    config_dict['Attribute Archive'] = config_parts[32]
    config_dict['Modify Creation Date'] = config_parts[33]
    config_dict['Modified Creation Data'] = config_parts[34]
    config_dict['Thread Persistance'] = config_parts[35]
    config_dict['Anti-ZoneAlarm'] = config_parts[36]
    config_dict['Anti-SpyTheSpy'] = config_parts[37]
    config_dict['Anti-NetStat'] = config_parts[38]
    config_dict['Anti-TiGeRFirewall'] = config_parts[39]
    config_dict['Anti-TCPview'] = config_parts[40]
    config_dict['Anti-CurrentPorts'] = config_parts[41]
    config_dict['Anti-RogueKiller'] = config_parts[42]
    config_dict['Enable MessageBox'] = config_parts[43]
    config_dict['MessageBox Message'] = config_parts[44]
    config_dict['MessageBox Icon'] = config_parts[45]
    config_dict['MessageBox Buttons'] = config_parts[46]
    config_dict['MessageBox Title'] = config_parts[47]    
    if config_parts[6] == 1:
        config_dict['Install Path'] = 'Temp'
    if config_parts[7] == 1:
        config_dict['Install Path'] = 'Windows'
    if config_parts[11] == 1:
        config_dict['Install Path'] = 'System32'
    if config_parts[12] == 1:
        config_dict['Install Path'] = 'Program Files'
    return config_dict


def ver_5(data):
    config_dict = {}
    config_parts = data.split('!!ElMattadorDz!!')
    config_dict['Domain'] = config_parts[1] 
    config_dict['Port'] = config_parts[2] 
    config_dict['Disable Registry'] = config_parts[3]
    config_dict['Disbale TaskManager'] = config_parts[4] 
    config_dict['Install Server'] = config_parts[5] 
    config_dict['Registry Key'] = config_parts[8] 
    config_dict['Install Name'] = config_parts[9] 
    config_dict['Disbale UAC'] = config_parts[10]
    config_dict['Anti-Sandboxie'] = config_parts[13]
    config_dict['Anti-Anubis'] = config_parts[14]
    config_dict['Anti-VirtualBox'] = config_parts[15]
    config_dict['Anti-VmWare'] = config_parts[16]
    config_dict['Anti-VirtualPC'] = config_parts[17]
    config_dict['ServerID'] = config_parts[18]
    config_dict['USB Spread'] = config_parts[19] 
    config_dict['P2P Spread'] = config_parts[20] 
    config_dict['RAR Spread'] = config_parts[21]
    config_dict['MSN Spread'] = config_parts[22]
    config_dict['Yahoo Spread'] = config_parts[23]
    config_dict['LAN Spread'] = config_parts[24]
    config_dict['Disbale Firewall'] = config_parts[25] 
    config_dict['Delay Execution MiliSeconds'] = config_parts[26] 
    if config_parts[6] == 1: 
        config_dict['Install Path'] = 'Temp'
    if config_parts[7] == 1: 
        config_dict['Install Path'] = 'Windows'
    if config_parts[11] == 1: 
        config_dict['Install Path'] = 'System32'
    if config_parts[12] == 1: 
        config_dict['Install Path'] = 'Program Files'
    return [config_dict, [config_dict['Domain']]]

def config(data):
    if '!!<3SAFIA<3!!' in data:
        config_dict = ver_52(data)
        return config_dict

    elif '!!ElMattadorDz!!' in data:
        config_dict = ver_5(data)
        return config_dict
