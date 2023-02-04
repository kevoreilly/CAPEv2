# Copyright (C) 2020 ditekshen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature


class NetworkDNSTunnelingRequest(Signature):
    name = "network_dns_tunneling_request"
    description = "Generates suspicious DNS queries indicative of DNS tunneling"
    severity = 2
    categories = ["network", "dns"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1094"]  # MITRE v6
    ttps += ["T1048", "T1071", "T1095"]  # MITRE v6,7,8
    ttps += ["T1071.004"]  # MITRE v7,8
    mbcs = ["OB0004", "B0030"]
    mbcs += ["OC0006", "C0011"]  # micro-behaviour

    filter_apinames = set(["DnsQuery_A", "DnsQuery_W"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.qcount = int()
        self.match = False
        # base16, bas32, bas32hex, bas64, morse code
        self.patterns = [
            re.compile(".*(\.)?[A-Fa-f0-9-_]{12,}.*"),
            re.compile(".*(\.)?[A-Z2-7-_]{15,}.*"),
            re.compile(".*(\.)?[A-V0-9-_]{15,}.*"),
            re.compile(".*(\.)?[A-Za-z0-9-_]{20,}.*"),
            re.compile("^([01\.]{3,}){5,}.*"),
        ]
        self.dwhitelist = [
            ".inaddr.arpa",
            ".ip6.arpa",
            ".apple.com",
        ]

    def on_call(self, call, process):
        qtype = self.get_argument(call, "Type")
        qname = self.get_argument(call, "Name")
        if qtype and qname:
            labels = qname.split(".")
            if labels:
                mdomain = labels[len(labels) - 2] + "." + labels[len(labels) - 1]
                if mdomain:
                    if mdomain not in self.dwhitelist:
                        for pat in self.patterns:
                            if re.match(pat, qname):
                                self.qcount += 1
                                self.match = True
                                if self.pid:
                                    self.mark_call()
                        if len(qname) > 50:
                            self.qcount += 1
                            self.match = True
                            if self.pid:
                                self.mark_call()

    def on_complete(self):
        if self.match and self.qcount > 5:
            return True

        return False


class NetworkDNSIDN(Signature):
    name = "network_dns_idn"
    description = "Generates a DNS query to IDN/Punycode domain"
    severity = 2
    categories = ["network", "dns"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071"]  # MITRE v6,7,8
    ttps += ["T1071.004"]  # MITRE v7,8
    mbcs = ["OC0006", "C0011"]  # micro-behaviour

    filter_apinames = set(["DnsQueryA"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False

    def on_call(self, call, process):
        qname = self.get_argument(call, "Name")
        if qname:
            if qname.startswith("xn--"):
                self.match = True
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        return self.match


class NetworkDNSSuspiciousQueryType(Signature):
    name = "network_dns_suspicious_querytype"
    description = "Generates less common DNS request type"
    severity = 2
    categories = ["network", "dns"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1094"]  # MITRE v6
    ttps += ["T1048", "T1071"]  # MITRE v6,7,8
    ttps += ["T1071.004", "T1095"]  # MITRE v7,8
    mbcs = ["OC0006", "C0011"]  # micro-behaviour

    filter_apinames = set(["DnsQueryA"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.match = False
        self.qtype_whitelist = [1, 2, 5, 10, 12, 15, 16, 28, 255]

    def on_call(self, call, process):
        self.qtype = self.get_argument(call, "Type")
        if self.qtype:
            if self.qtype not in self.qtype_whitelist:
                self.match = True
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        return self.match


class NetworkDNSBlockChain(Signature):
    name = "network_dns_blockchain"
    description = "Generates DNS query to Blockchain domain or TLD"
    severity = 2
    categories = ["network", "dns"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071"]  # MITRE v6,7,8
    ttps += ["T1071.004"]  # MITRE v7,8
    mbcs = ["OC0006", "C0011"]  # micro-behaviour

    def run(self):
        domain_indictors = [
            ".*\.bazar$",
            ".*\.bit$",
            ".*\.coin$",
            ".*\.emc$",
            ".*\.lib$",
            "^ns(1|2)\.new-nations\.(ku|te|ti|uu|ko|rm)$",
            "^seed(1|2)\.emercoin\.com$",
        ]

        for indicator in domain_indictors:
            if self.check_domain(pattern=indicator, regex=True):
                self.data.append({"domain": indicator})
                return True

        return False


class NetworkDNSOpenNIC(Signature):
    name = "network_dns_opennic"
    description = "Queries OpenNIC server or TLD"
    severity = 2
    categories = ["network", "dns"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071"]  # MITRE v6,7,8
    ttps += ["T1071.004"]  # MITRE v7,8
    mbcs = ["OC0006", "C0011"]  # micro-behaviour

    def run(self):
        domain_indictors = [
            ".*\.bbs$",
            ".*\.chan$",
            ".*\.dns\.opennic\.glue$",
            ".*\.cyb$",
            ".*\.cyb\.uptime\.party$",
            ".*\.dyn$",
            ".*\.epic\.okashi\.me$",
            ".*\.fur$",
            ".*\.geek$",
            ".*\.gopher$",
            ".*\.indy$",
            ".*\.libre$",
            ".*\.neo$",
            ".*\.null$",
            ".*\.o$",
            ".*\.opennic\.epic$",
            ".*\.oss$",
            ".*\.oz$",
            ".*\.parody$",
            ".*\.pirate$",
        ]

        for indicator in domain_indictors:
            if self.check_domain(pattern=indicator, regex=True):
                self.data.append({"domain": indicator})
                return True

        return False


class NetworkDOHTLS(Signature):
    name = "network_dns_doh_tls"
    description = "Queries or connects to DNS-Over-HTTPS/DNS-Over-TLS domain or IP address"
    severity = 2
    categories = ["network", "dns"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071"]  # MITRE v6,7,8
    ttps += ["T1071.004", "T1071.001"]  # MITRE v7,8
    mbcs = ["OC0006", "C0011"]  # micro-behaviour

    def run(self):
        domain_indicators = [
            "cloudflare-dns.com",
            "commons.host",
            "dns10.quad9.net",
            "dns.233py.com",
            "dns9.quad9.net",
            "dns.aaflalo.me",
            "dns.adguard.com",
            "dns.bitgeek.in",
            "dns.cmrg.net",
            "dns.dns-over-https.com",
            "dns.dnsoverhttps.net",
            "dns.larsdebruin.net",
            "dns.neutopia.org",
            "dns.nextdns.io",
            "dns-nyc.aaflalo.me",
            "dns.oszx.co",
            "dnsovertls2.sinodun.com",
            "dnsovertls3.sinodun.com",
            "dns.rubyfish.cn",
            "dns-tls.bitwiseshift.net",
            "doh.appliedprivacy.net",
            "doh.armadillodns.net",
            "doh.captnemo.in",
            "doh-ch.blahdns.com",
            "doh.cleanbrowsing.org",
            "doh.crypto.sx",
            "doh-de.blahdns.com",
            "doh.dns.sb",
            "doh.dnswarden.com",
            "doh-jp.blahdns.com",
            "doh.li",
            "doh.netweaver.uk",
            "doh.powerdns.org",
            "doh.securedns.eu",
            "doh.tiar.app",
            "dot1.appliedprivacy.net",
            "dot1.dnswarden.com",
            "dot2.dnswarden.com",
            "dot-de.blahdns.com",
            "dot-jp.blahdns.com",
            "ea-dns.rubyfish.cn",
            "edns.233py.com",
            "family.adguard.com",
            "iana.tenta.io",
            "ibksturm.synology.me",
            "jp.tiar.app",
            "kaitain.restena.lu",
            "ndns.233py.com",
            "ns1.dnsprivacy.at",
            "ns2.dnsprivacy.at",
            "one.one.one.one",
            "opennic.tenta.io",
            "privacydns.go6lab.si",
            "rdns.faelix.net",
            "sdns.233py.com",
            "tls-dns-u.odvr.dns-oarc.net",
            "unicast.censurfridns.dk",
            "uw-dns.rubyfish.cn",
            "wdns.233py.com",
        ]

        ip_indicators = [
            "1.0.0.1",
            "1.1.1.1",
            "9.9.9.9",
            "9.9.9.10",
            "37.252.185.229",
            "37.252.185.232",
            "45.32.105.4",
            "45.32.253.116",
            "45.77.124.64",
            "45.90.28.0",
            "46.101.66.244",
            "46.227.200.54",
            "46.227.200.55",
            "47.96.179.163",
            "47.99.165.31",
            "47.101.136.37",
            "51.15.70.167",
            "51.38.83.141",
            "66.244.159.100",
            "66.244.159.200",
            "78.56.95.145",
            "80.67.188.188",
            "81.187.221.24",
            "89.233.43.71",
            "89.234.186.112",
            "94.130.110.178",
            "94.130.110.185",
            "99.192.182.100",
            "99.192.182.200",
            "104.16.248.249",
            "104.16.249.249",
            "104.28.0.106",
            "104.28.1.106",
            "104.236.178.232",
            "108.61.201.119",
            "114.115.240.175",
            "115.159.154.226" "116.203.35.255",
            "116.203.70.156",
            "118.24.208.197",
            "118.89.110.78",
            "119.29.107.85",
            "136.144.215.158",
            "139.59.48.222",
            "139.59.51.46",
            "145.100.185.17",
            "145.100.185.18",
            "146.185.167.43",
            "149.112.112.9",
            "149.112.112.10",
            "158.64.1.29",
            "159.69.198.101",
            "168.235.81.167",
            "172.64.202.17",
            "172.64.203.17",
            "172.104.93.80",
            "176.56.236.175",
            "176.103.130.130",
            "176.103.130.131",
            "178.82.102.190",
            "184.105.193.78",
            "185.134.196.54",
            "185.134.197.54",
            "185.157.233.92",
            "185.184.222.222",
            "185.222.222.222",
            "185.228.168.10",
            "185.228.168.168",
            "199.58.81.218",
            "200.1.123.46",
            "206.189.215.75",
        ]

        found_matches = False

        for indicator in domain_indicators:
            if self.check_domain(pattern=indicator):
                self.data.append({"domain": indicator})
                found_matches = True

        for indicator in ip_indicators:
            if self.check_ip(pattern=indicator):
                self.data.append({"ip": indicator})
                found_matches = True

        return found_matches


class NetworkDNSReverseProxy(Signature):
    name = "network_dns_reverse_proxy"
    description = "DNS query to online reverse proxy detected"
    severity = 2
    categories = ["network", "dns"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071"]  # MITRE v6,7,8
    ttps += ["T1071.001", "T1071.004"]  # MITRE v7,8
    mbcs = ["OC0006", "C0011"]  # micro-behaviour

    def run(self):
        domain_indictors = [
            ".*\.portmap\.io$",
            ".*\.ngrok\.io$",
        ]

        for indicator in domain_indictors:
            if self.check_domain(pattern=indicator, regex=True):
                self.data.append({"domain": indicator})
                return True

        return False


class NetworkDNSTempFileService(Signature):
    name = "network_dns_temp_file_storage"
    description = "DNS query to anonymous/temporary file storage service detected"
    severity = 2
    categories = ["network"]
    authors = ["ditekshen"]
    minimum = "1.2"

    def run(self):
        domain_indicators = [
            "plik.root.gg",
            "gp.tt",
            "wetransfer.com",
            "send-anywhere.com",
            "sendgb.com",
            "send.firefox.com",
            "volafile.org",
            "uploadfiles.io",
            "sendpace.com",
            "filedropper.com",
            "myairbridge.com",
            "u.teknik.io",
            "upload.sexy",
            "digitalassets.ams3.digitaloceanspaces.com",
            "api.sendspace.com",
            "www.fileden.com",
            "a.pomf.cat",
            "dropmb.com",
            "transfer.sh",
            "1fichier.com",
        ]

        for indicator in domain_indicators:
            if self.check_domain(pattern=indicator, regex=True):
                self.data.append({"domain": indicator})
                return True

        return False


class NetworkDNSPasteSite(Signature):
    name = "network_dns_paste_site"
    description = "DNS query to a paste site or service detected"
    severity = 2
    categories = ["network"]
    authors = ["ditekshen"]
    minimum = "1.2"

    def run(self):
        domain_indicators = [
            "pastebin.com",
            "paste.ee",
            "pastecode.xyz",
            "rentry.co",
            "paste.nrecom.net",
            "hastebin.com",
            "privatebin.info",
            "penyacom.org",
            "controlc.com",
            "tiny-paste.com",
            "paste.teknik.io",
            "privnote.com",
            "hushnote.herokuapp.com",
            "justpaste.it",
            "stikked.ch",
            "dpaste.com",
            "pastebin.pl",
        ]

        for indicator in domain_indicators:
            if self.check_domain(pattern=indicator, regex=True):
                self.data.append({"domain": indicator})
                return True

        return False


class NetworkDNSURLShortener(Signature):
    name = "network_dns_url_shortener"
    description = "DNS query to URL Shortener site or service"
    severity = 2
    categories = ["network"]
    authors = ["ditekshen"]
    minimum = "1.2"

    def run(self):
        domain_indicators = [
            "bit.ly",
            "cutt.ly",
            "goo.gl",
            "www.shorturl.at",
            "n9.cl",
            "is.gd",
            "rb.gy",
            "long.af",
            "ykm.de",
            "ito.mx",
            "me2.do",
            "bit.do",
            "coki.me",
            "hyp.ae",
            "iurl.vip",
            "42url.com",
            "t.ly",
            "rebrand.ly",
            "2no.co",
        ]

        for indicator in domain_indicators:
            if self.check_domain(pattern=indicator, regex=True):
                self.data.append({"domain": indicator})
                return True

        return False


class NetworkDNSTempURLDNS(Signature):
    name = "network_dns_temp_urldns"
    description = "DNS query to temporary URL or DNS site or service detected"
    severity = 2
    categories = ["network"]
    authors = ["ditekshen"]
    minimum = "1.2"

    def run(self):
        domain_indicators = [
            ".*\.requestbin.net$",
        ]

        for indicator in domain_indicators:
            if self.check_domain(pattern=indicator, regex=True):
                self.data.append({"domain": indicator})
                return True

        return False


class Suspicious_TLD(Signature):
    name = "suspicious_tld"
    description = "Resolves a suspicious Top Level Domain (TLD)"
    severity = 2
    categories = ["network"]
    # Migrated by @CybercentreCanada
    authors = ["RedSocks", "Kevin Ross", "@CybercentreCanada"]
    minimum = "1.2"

    def run(self):
        domains_re = [
            (".*\\.by$", "Belarus domain TLD"),
            (".*\\.cc$", "Cocos Islands domain TLD"),
            (".*\\.onion$", "TOR hidden services domain TLD"),
            (".*\\.pw$", "Palau domain TLD"),
            (".*\\.ru$", "Russian Federation domain TLD"),
            (".*\\.su$", "Soviet Union domain TLD"),
            (".*\\.top$", "Generic top level domain TLD"),
        ]
        queried_domains = []

        for indicator in domains_re:
            matches = self.check_domain(pattern=indicator[0], regex=True, all=True)
            if matches:
                for tld in matches:
                    if tld not in queried_domains:
                        queried_domains.append(tld)
                        self.data.append({"domain": tld})

        if len(self.data) > 0:
            return True
        else:
            return False
