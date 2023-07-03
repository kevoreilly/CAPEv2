from configparser import ConfigParser
from lib.cuckoo.common.abstracts import CUCKOO_ROOT
import os
from collections import defaultdict

# Read the config file
def mapTTP(oldTTPs:list):
    config = ConfigParser()
    configPath = os.path.join(CUCKOO_ROOT, 'TTPs.conf')
    config.read(configPath)

    ttpsList = []
    for ttpObj in oldTTPs:
        for option in config.options('TTPs'):
            if '.' in ttpObj['ttp']:
                break
            elif ttpObj['ttp'] == option.upper():
                ttpObj['ttp'] = config.get('TTPs', option)
                ttpsList.append(ttpObj)
                break
    grouped_ttps = defaultdict(list)

    for item in ttpsList:
        grouped_ttps[item['signature']].append(item['ttp'])

    return [{'signature': signature, 'ttps': list(dict.fromkeys(ttps))} for signature, ttps in grouped_ttps.items()]