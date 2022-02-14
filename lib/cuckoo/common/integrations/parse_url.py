# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
from datetime import datetime

try:
    import re2 as re
except ImportError:
    import re

try:
    from whois import whois

    HAVE_WHOIS = True
except Exception:
    HAVE_WHOIS = False

try:
    import bs4

    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False


import requests

log = logging.getLogger(__name__)


class URL(object):
    """URL 'Static' Analysis"""

    def __init__(self, url):
        self.url = url
        p = r"^(?:https?:\/\/)?(?:www\.)?(?P<domain>[^:\/\n]+)"
        dcheck = re.match(p, self.url)
        if dcheck:
            self.domain = dcheck.group("domain")
            # Work around a bug where a "." can tail a url target if
            # someone accidentally appends one during submission
            while self.domain.endswith("."):
                self.domain = self.domain[:-1]
        else:
            self.domain = ""

    def parse_json_in_javascript(self, data=str(), ignore_nest_level=0):
        nest_count = 0 - ignore_nest_level
        string_buf = str()
        json_buf = []
        json_data = []
        for character in data:
            if character == "{":
                nest_count += 1
            if nest_count > 0:
                string_buf += character
            if character == "}":
                nest_count -= 1
            if nest_count == 0 and len(string_buf):
                json_buf.append(string_buf)
                string_buf = str()

        if json_buf:
            for data in json_buf:
                if len(data) > 4:
                    json_data.append(json.loads(data))
            return json_data

        return []

    def run(self):
        results = {}
        if self.domain:
            try:
                w = whois(self.domain)
                results["url"] = {}
                # Create static fields if they don't exist, EG if the WHOIS
                # data is stale.
                fields = [
                    "updated_date",
                    "status",
                    "name",
                    "city",
                    "expiration_date",
                    "zipcode",
                    "domain_name",
                    "country",
                    "whois_server",
                    "state",
                    "registrar",
                    "referral_url",
                    "address",
                    "name_servers",
                    "org",
                    "creation_date",
                    "emails",
                ]
                for field in fields:
                    if field not in list(w.keys()) or not w[field]:
                        w[field] = ["None"]
            except Exception:
                # No WHOIS data returned
                log.warning("No WHOIS data for domain: %s", self.domain)
                return results

            # These can be a list or string, just make them all lists
            for key in w.keys():
                buf = []
                # Handle and format dates
                if "_date" in key:
                    if isinstance(w[key], list):
                        buf = [str(dt).replace("T", " ").split(".", 1)[0] for dt in w[key]]
                    else:
                        buf = [str(w[key]).replace("T", " ").split(".", 1)[0]]
                else:
                    if isinstance(w[key], list):
                        continue
                    else:
                        buf = [w[key]]
                w[key] = buf

            output = (
                "Name: {0}\nCountry: {1}\nState: {2}\nCity: {3}\n"
                "ZIP Code: {4}\nAddress: {5}\n\nOrginization: {6}\n"
                "Domain Name(s):\n    {7}\nCreation Date:\n    {8}\n"
                "Updated Date:\n    {9}\nExpiration Date:\n    {10}\n"
                "Email(s):\n    {11}\n\nRegistrar(s):\n    {12}\nName "
                "Server(s):\n    {13}\nReferral URL(s):\n    {14}"
            )
            output = output.format(
                w["name"][0],
                w["country"][0],
                w["state"][0],
                w["city"][0],
                w["zipcode"][0],
                w["address"][0],
                w["org"][0],
                "\n    ".join(w["domain_name"]),
                "\n    ".join(w["creation_date"]),
                "\n    ".join(w["updated_date"]),
                "\n    ".join(w["expiration_date"]),
                "\n    ".join(w["emails"]),
                "\n    ".join(w["registrar"]),
                "\n    ".join(w["name_servers"]),
                "\n    ".join(w["referral_url"]),
            )
            results["url"]["whois"] = output

        # ToDo this should be in config
        if self.domain == "bit.ly":
            resp = requests.get(f"{self.url}+")
            soup = bs4.BeautifulSoup(resp.text, "html.parser")
            output = []
            for script in [x.extract() for x in soup.find_all("script")]:
                if script.contents:
                    content = script.contents[0]
                    if "long_url_no_protocol" in content:
                        output = self.parse_json_in_javascript(content, 1)

            if output:
                results["url"]["bitly"] = {k: v for d in output for k, v in d.iteritems()}
                newtime = datetime.fromtimestamp(int(results["url"]["bitly"]["created_at"]))
                results["url"]["bitly"]["created_at"] = f"{newtime.strftime('%Y-%m-%d %H:%M:%S')} GMT"

        return results
