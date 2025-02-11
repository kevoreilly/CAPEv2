import base64
import json
import logging

import requests
from urllib3.exceptions import InsecureRequestWarning

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.utils import add_family_detection

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

log = logging.getLogger(__name__)

MANDIANT_AUTH_URL = "https://api.intelligence.mandiant.com/token"
MANDIANT_SEARCH_URL = "https://api.intelligence.mandiant.com/v4/search"

integragrations_conf = Config("integrations")

api_access = integragrations_conf.mandiant_intel.api_access
api_secret = integragrations_conf.mandiant_intel.api_secret


class MandiantAPIClient:
    def __init__(self):
        self.api_access = api_access
        self.api_secret = api_secret
        self.auth_url = MANDIANT_AUTH_URL
        self.search_url = MANDIANT_SEARCH_URL
        self.token = None

    def _generate_auth_header(self):
        auth_token_bytes = f"{self.api_access}:{self.api_secret}".encode("ascii")
        base64_auth_token_bytes = base64.b64encode(auth_token_bytes)
        return base64_auth_token_bytes.decode("ascii")

    def get_new_token(self):
        if self.token:
            return

        headers = {
            "Authorization": f"Basic {self._generate_auth_header()}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "X-App-Name": "get-indicator-infos",
        }
        params = {"grant_type": "client_credentials"}

        try:
            response = requests.post(url=self.auth_url, headers=headers, verify=False, allow_redirects=False, data=params)
        except Exception as e:
            return {"error": True, "msg": f"Error during token request: {e}"}

        if response.status_code == 200:
            self.token = response.json().get("access_token")
            return self.token
        else:
            return {"error": True, "msg": f"Failed to obtain token from server: {response.status_code}"}

    def search(self, indicator):
        if not self.token:
            log.error("No valid token available. Please authenticate first.")
            return

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-App-Name": "get-indicator-infos",
        }

        body = {
            "search": f"{indicator}",
            "type": "all",
            "limit": 50,
            "sort_by": ["relevance"],
            "sort_order": "asc",
            "next": "",
        }

        try:
            response = requests.post(
                url=self.search_url, headers=headers, verify=False, allow_redirects=False, data=json.dumps(body)
            )
        except Exception as e:
            return {"error": True, "msg": f"Error during search request: {e}"}

        if response.status_code == 200:
            return self.parse_response(response.json())
        elif response.status_code == 401:
            self.token = None
            if self.get_new_token():
                return self.search(indicator)
            else:
                log.error("Failed to refresh token.")
                return
        else:
            return {"error": True, "msg": f"Search failed: {response.status_code}"}

    def parse_response(self, response):
        actors = []
        malwares = []
        objects = response.get("objects")
        if not objects:
            return

        for obj in objects:
            if "actors" in obj:
                actors.extend(actor.get("name") for actor in obj["actors"] if "name" in actor)
            if "malwares" in obj:
                malwares.extend(malware.get("name") for malware in obj["malwares"] if "name" in malware)

        return {"actor": actors, "malware": malwares}


def mandiant_lookup(category: str, target: str, results: dict = {}):
    if not integragrations_conf.mandiant_intel.enabled:
        return results

    mandiant_intel = {}

    if category == "file":
        sha256 = False
        if not path_exists(target) and len(target) != 64:
            return {"error": True, "msg": "File doesn't exist"}

        sha256 = target if len(target) == 64 else File(target).get_sha256()
        client = MandiantAPIClient()
        mandiant_intel = {}
        mandiant_intel["sha256"] = sha256
        if client.get_new_token():
            result = client.search(sha256)
            if result:
                mandiant_intel["detections"] = result
                names = result.get("malware", [])
                for name in names:
                    add_family_detection(results, name, "Mandiant", sha256)

    return mandiant_intel


if __name__ == "__main__":
    import sys

    indicator = sys.argv[1]

    client = MandiantAPIClient()

    if client.get_new_token():
        result = client.search(indicator)
        if result:
            print(json.dumps(result, indent=4))
