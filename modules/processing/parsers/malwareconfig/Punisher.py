def config(data):
    config_dict = {}
    config_parts = data.split('abccba')
    if len(config_parts) > 5:
        config_dict['Domain'] = config_parts[1]
        config_dict['Port'] = config_parts[2]
        config_dict['Campaign Name'] = config_parts[3]
        config_dict['Copy StartUp'] = config_parts[4]
        config_dict['Unknown'] = config_parts[5]
        config_dict['Add To Registry'] = config_parts[6]
        config_dict['Registry Key'] = config_parts[7]
        config_dict['Password'] = config_parts[8]
        config_dict['Anti Kill Process'] = config_parts[9]
        config_dict['USB Spread'] = config_parts[10]
        config_dict['Anti VMWare VirtualBox'] = config_parts[11]
        config_dict['Kill Sandboxie'] = config_parts[12]
        config_dict['Kill WireShark / Apate DNS'] = config_parts[13]
        config_dict['Kill NO-IP'] = config_parts[14]
        config_dict['Block Virus Total'] = config_parts[15]
        config_dict['Install Name'] = config_parts[16]
        config_dict['ByPass Malware Bytes'] = config_parts[20]
        config_dict['Kill SpyTheSPy'] = config_parts[21]
        config_dict['Connection Delay'] = config_parts[22]
        config_dict['Copy To All Drives'] = config_parts[23]
        config_dict['HideProcess'] = config_parts[24]
        if config_parts[17] == 'True':
            config_dict['Install Path'] = 'App Data'
        if config_parts[18] == 'True':
            config_dict['Install Path'] = 'TEMP'
        if config_parts[19] == 'True':
            config_dict['Install Path'] = 'Documents'
        return config_dict
    else:
        return None