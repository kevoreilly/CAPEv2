import requests
import re
import os
from lib.cuckoo.core.plugins import list_plugins
import modules.signatures
from lib.cuckoo.core.plugins import import_package
from configparser import ConfigParser
from lib.cuckoo.common.abstracts import CUCKOO_ROOT


def mapMitre(oldID):
    # Step 2: Fetch the mapping documentation
    MITRE_URL = f'https://attack.mitre.org/techniques/{oldID}'

    response = requests.get(MITRE_URL)
    if response.status_code == 200:
         match1 = re.search(rb'url=([^"]+)"', response.content)
         if match1:
             url = match1.group(1).decode('utf-8')
             pattern = r"\/techniques\/(\w+)(?:\/(\d+))?"
             matches = re.search(pattern, url)
             if matches:
                ttp_id = matches.group(1)
                sub_id = matches.group(2) if matches.group(2) else ""
                # Create the final output with TTP ID and sub ID
                final_output = f"{ttp_id}.{sub_id}" if sub_id else ttp_id
                return final_output  # Output: T1218.004 if sub ID exists, otherwise T1218
         else:
            return oldID


if __name__ == "__main__":
    configPath = os.path.join(CUCKOO_ROOT, 'TTPs.conf')
    config = ConfigParser()
    ttpDict = {}
    import_package(modules.signatures)
    for sig in list_plugins(group="signatures"):
        if sig.ttps == []:
            continue
    #     print(sig.name)
        for ttp in sig.ttps:
            if '.' in ttp or 'U' in ttp or 'S' in ttp:
                continue
            ttpDict[ttp] = mapMitre(ttp)

    config.add_section('TTPs')
    # Loop through the dictionary and add options and values to the ConfigParser object
    for option, value in ttpDict.items():
        config.set('TTPs', option, value)

    # Save the configuration to a file
    with open(configPath, 'w') as configfile:
        config.write(configfile)
    print('Done')
    #print(mapMitre("T1215"))
