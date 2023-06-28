from configparser import ConfigParser
from lib.cuckoo.common.abstracts import CUCKOO_ROOT
import os

# Read the config file
def mapTTP(oldTTPs:list):
    config = ConfigParser()
    configPath = os.path.join(CUCKOO_ROOT, 'conf', 'TTPs.conf')
    config.read(configPath)

    for ttpObj in oldTTPs:
        for option in config.options('TTPs'):
            if '.' in ttpObj['ttp']:
                ttpObj.clear()
                break
            elif ttpObj['ttp'] == option.upper():
                ttpObj['ttp'] = config.get('TTPs', option)
    return oldTTPs