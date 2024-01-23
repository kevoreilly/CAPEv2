import json
import os
from collections import defaultdict

from lib.cuckoo.common.abstracts import CUCKOO_ROOT

ttpDict = {}
ttps_map_file = os.path.join(CUCKOO_ROOT, "data", "mitre", "TTPs.json")
if os.path.exists(ttps_map_file):
    try:
        ttpDict = json.loads(open(ttps_map_file, "r").read())
    except Exception as e:
        print("Can't load TTPs.json file", e)

# Read the config file
def mapTTP(oldTTPs: list, mbcs: list):
    ttpsList = []
    grouped_ttps = defaultdict(list)

    for ttpObj in oldTTPs:
        if "." in ttpObj["ttp"]:
            continue
        elif ttpDict.get(ttpObj["ttp"]):
            ttpObj["ttp"] = ttpDict.get(ttpObj["ttp"])
            ttpsList.append(ttpObj)
            continue

    for item in ttpsList:
        grouped_ttps[item["signature"]].append(item["ttp"])

    return [
        {"signature": signature, "ttps": list(dict.fromkeys(ttps)), "mbcs": mbcs.get(signature, [])}
        for signature, ttps in grouped_ttps.items()
    ]
