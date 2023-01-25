# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
from datetime import datetime
from typing import List

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


class URL:
    """URL 'Static' Analysis"""

    def __init__(self, url: str):
        self.url = url
        dcheck = re.match(r"^(?:https?:\/\/)?(?:www\.)?(?P<domain>[^:\/\n]+)", self.url)
        if dcheck:
            self.domain = dcheck.group("domain")
            # Work around a bug where a "." can tail a url target if
            # someone accidentally appends one during submission
            self.domain = self.domain.rstrip(".")
        else:
            self.domain = ""

    def parse_json_in_javascript(self, data: str = "", ignore_nest_level: int = 0) -> List[dict]:
        nest_count = -ignore_nest_level
        string_buf = ""
        json_buf = []
        for character in data:
            if character == "{":
                nest_count += 1
            if nest_count > 0:
                string_buf += character
            if character == "}":
                nest_count -= 1
            if nest_count == 0 and string_buf:
                json_buf.append(string_buf)
                string_buf = ""

        if json_buf:
            return [json.loads(data) for data in json_buf if len(data) > 4]

        return []

    def run(self) -> dict:
        results = {}
        if self.domain:
            try:
                w = whois(self.domain)
                # Create static fields if they don't exist, EG if the WHOIS
                # data is stale.
                fields = (
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
                )
                for field in fields:
                    if not w.get(field):
                        w[field] = ["None"]
            except Exception:
                # No WHOIS data returned
                log.warning("No WHOIS data for domain: %s", self.domain)
                return results

            # These can be a list or string, just make them all lists
            for key in w:
                buf = []
                # Handle and format dates
                if "_date" in key:
                    buf = (
                        [str(dt).replace("T", " ").split(".", 1)[0] for dt in w[key]]
                        if isinstance(w[key], list)
                        else [str(w[key]).replace("T", " ").split(".", 1)[0]]
                    )

                elif isinstance(w[key], list):
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
            results["whois"] = output

        # TODO: this should be in config
        if self.domain == "bit.ly":
            resp = requests.get(f"{self.url}+")
            soup = bs4.BeautifulSoup(resp.text, "html.parser")
            output = []
            for script in (x.extract() for x in soup.find_all("script")):
                if script.contents:
                    content = script.contents[0]
                    if "long_url_no_protocol" in content:
                        output = self.parse_json_in_javascript(content, 1)

            if output:
                results["bitly"] = {k: v for d in output for k, v in d.items()}
                newtime = datetime.fromtimestamp(int(results["bitly"]["created_at"]))
                results["bitly"]["created_at"] = f"{newtime.strftime('%Y-%m-%d %H:%M:%S')} GMT"

        return results
