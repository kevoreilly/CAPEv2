import json

import requests

names = []
malpedia_url = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json"

r = requests.get(malpedia_url)
if r.ok:
    names = [v["value"] for v in r.json().get("values", [])]
    if names:
        with open("malpedia.json", "wt") as f:
            f.write(json.dumps(names))
