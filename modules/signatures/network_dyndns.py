# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class NetworkDynDNS(Signature):
    name = "network_dyndns"
    description = "Connects to a Dynamic DNS Domain"
    severity = 2
    categories = ["network"]
    authors = ["RedSocks"]
    minimum = "1.2"
    ttps = ["T1568"]

    def run(self):
        domains_re = [
            ".*\\.no-ip\\.",
            ".*\\.strangled\\.net",
            ".*\\.noip\\.",
            ".*\\.x64\\.me",
            ".*\\.ddns\\.",
            ".*\\.myvnc\\.com",
            ".*\\.user32\\.com",
            ".*\\.dyndns\\.",
            ".*\\.codns\\.com",
            ".*\\.servebeer\\.",
            ".*\\.serveminecraft\\.",
            ".*\\.servebbs\\.",
            ".*\\.serveblog\\.",
            ".*\\.servecounterstrike\\.",
            ".*\\.ntdll\\.net",
            ".*\\.servehttp\\.",
            ".*\\.bounceme\\.net",
            ".*\\.servequake\\.com",
            ".*\\.3utilities\\.",
            ".*\\.redirectme\\.net",
            ".*\\.servehalflife\\.com",
            ".*\\.gicp\\.net",
            ".*\\.zapto\\.org",
            ".*\\.hopto\\.org",
            ".*\\.tftpd\\.net",
            ".*\\.myq-see\\.com",
            ".*\\.3322\\.org",
            ".*\\.8866\\.org",
            ".*\\.sytes\\.net",
            ".*\\.serveftp\\.",
            ".*\\.servemp3\\.",
            ".*\\.mooo\\.com",
            ".*\\.dnsget\\.org",
            ".*\\.f3322\\.org",
            ".*\\.publicvm\\.com",
            ".*\\.dlinkddns\\.com",
            ".*\\.authorizeddns\\.",
            ".*\\.chickenkiller\\.",
            ".*\\.8800\\.org",
            ".*\\.adultdns\\.",
            ".*\\.myfreeip\\.",
            ".*\\.linkpc\\.net",
            ".*\\.myftp\\.",
            ".*\\.servegame\\.",
            ".*\\.ignorelist\\.",
            ".*\\.duckdns\\.org",
            ".*\\.ddnsking\\.",
            ".*\\.hopper\\.pw",
            ".*\\.couchpotatofries\\.",
            ".*\\.dyndns.*ip\\.com",
            ".*\\.dynamic-dns\\.net",
            ".*\\.now-ip.org\\.net",
            ".*\\.now-ip.net\\.net",
            ".*\\.now-ip.net\\.xyz",
            ".*\\.zapto\\.xyz",
            ".*\\.mypi\\.co",
            ".*\\.001www.com\\.com",
            ".*\\.16-b\\.it",
            ".*\\.32-b\\.it",
            ".*\\.64-b\\.it",
            ".*\\.crafting\\.xyz",
            ".*\\.forumz\\.info",
            ".*\\.hicam\\.net",
            ".*\\.myiphost\\.com",
            ".*\\.mypi\\.co",
            ".*\\.n4t\\.co",
            ".*\\.tcp4\\.me",
            ".*\\.x443\\.pw",
        ]

        found_matches = False
        for indicator in domains_re:
            matches = self.check_domain(pattern=indicator, regex=True, all=True)
            if matches:
                found_matches = True
                for match in matches:
                    self.data.append({"domain": match})

        return found_matches
