# Copyright (C) 2019 ditekshen
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

from lib.cuckoo.common.abstracts import Signature

class CheckIP(Signature):
    name = "network_doh"
    description = "Queries or connects to DNS-Over-HTTPS/DNS-Over-TLS domain or IP address"
    severity = 2
    categories = ["network"]
    authors = ["ditekshen"]
    minimum = "1.2"

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
            "115.159.154.226"
            "116.203.35.255",
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
                self.data.append({"domain" : indicator})
                found_matches = True

        for indicator in ip_indicators:
            if self.check_ip(pattern=indicator):
                self.data.append({"ip" : indicator})
                found_matches = True

        return found_matches
