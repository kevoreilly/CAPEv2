import json
import os
from collections import defaultdict

from lib.cuckoo.common.abstracts import CUCKOO_ROOT

ttpDict = {}
ttps_map_file = os.path.join(CUCKOO_ROOT, "data", "mitre", "TTPs.json")
if os.path.exists(ttps_map_file):
    try:
        with open(ttps_map_file, "r") as f:
            ttpDict = json.load(f)
    except Exception as e:
        print("Can't load TTPs.json file", e)


# Read the config file
def mapTTP(oldTTPs: list, mbcs: list):
    """
    Maps old TTPs (Tactics, Techniques, and Procedures) to a new format and groups them by signature.

    Args:
        oldTTPs (list): A list of dictionaries containing old TTPs. Each dictionary should have a "ttp" key.
        mbcs (list): A list of MBCs (Malware Behavior Catalog) mapped by signature.

    Returns:
        list: A list of dictionaries where each dictionary contains:
            - "signature" (str): The signature of the TTP.
            - "ttps" (list): A list of unique TTPs associated with the signature.
            - "mbcs" (list): A list of MBCs associated with the signature.
    """
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
