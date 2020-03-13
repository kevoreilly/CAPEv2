# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import socket
import struct
import tempfile
import logging
import dns.resolver
from collections import OrderedDict
from urllib.parse import urlunparse
from hashlib import md5
from json import loads
import six
from base64 import b64encode

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.dns import resolve
from lib.cuckoo.common.irc import ircMessage
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import convert_to_printable
from lib.cuckoo.common.exceptions import CuckooProcessingError
from dns.reversename import from_address
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.ja3.ja3 import parse_variable_array, convert_to_ja3_segment, process_extensions

try:
    import GeoIP

    IS_GEOIP = True
    gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
except ImportError:
    IS_GEOIP = False

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False

# Imports for the batch sort.
# http://stackoverflow.com/questions/10665925/how-to-sort-huge-files-with-python
# http://code.activestate.com/recipes/576755/
import heapq
from itertools import islice
from collections import namedtuple

TLS_HANDSHAKE = 22

Keyed = namedtuple("Keyed", ["key", "obj"])
Packet = namedtuple("Packet", ["raw", "ts"])

log = logging.getLogger(__name__)
cfg = Config()
proc_cfg = Config("processing")

enabled_whitelist = proc_cfg.network.dnswhitelist
whitelist_file = proc_cfg.network.dnswhitelist_file

class Pcap:
    """Reads network data from PCAP file."""

    def __init__(self, filepath, ja3_fprints):
        """Creates a new instance.
        @param filepath: path to PCAP file
        """
        self.filepath = filepath
        self.ja3_fprints = ja3_fprints

        # List of all hosts.
        self.hosts = []
        # List containing all non-private IP addresses.
        self.unique_hosts = []
        # List of unique domains.
        self.unique_domains = []
        # List containing all TCP packets.
        self.tcp_connections = []
        self.tcp_connections_seen = set()
        # List containing all UDP packets.
        self.udp_connections = []
        self.udp_connections_seen = set()
        # List containing all ICMP requests.
        self.icmp_requests = []
        # List containing all HTTP requests.
        self.http_requests = OrderedDict()
        # List containing all DNS requests.
        self.dns_requests = OrderedDict()
        self.dns_answers = set()
        # List containing all SMTP requests.
        self.smtp_requests = []
        # Reconstruncted SMTP flow.
        self.smtp_flow = {}
        # List containing all IRC requests.
        self.irc_requests = []
        # List containing all JA3 hashes.
        self.ja3_records = []
        # Dictionary containing all the results of this processing.
        self.results = {}
        # DNS Whitelist
        self.domain_whitelist = [
            # Certificate Trust Update domains
            "^ocsp\.usertrust\.com$",
            "\.windows\.com$",
            "^ocsp\.comodoca\.com$",
            "^ctldl\.windowsupdate\.com$",
            "^crl\.microsoft\.com$",
            "^urs\.microsoft\.com$",
            "\.microsoft\.com$",
            "\.skype\.com$",
            "\.live\.com$",
            "\.clients[0-9]+\.google\.com$",
            "\.googleapis\.com$",
            "\.gvt1\.com$",
            "\.msftncsi\.com$",
            "^apps\.identrust\.com$",
            "^isrg\.trustid\.ocsp\.identrust\.com$",
            "^urs\.microsoft\.com$",
            "^config\.edge\.skype\.com$",
            "^client-office365-tas\.msedge\.net$",
            "^files\.acrobat\.com$",
            "^acroipm2\.adobe\.com$",
            "^acroipm\.adobe\.com$",
            "^ocsp\.trust-provider\.com$",
            "^ocsp\.comodoca4\.com$",
            "^ocsp\.pki\.goog$",
            "^oneclient.sfx.ms$",

        ]
        if enabled_whitelist and whitelist_file:
             with open(os.path.join(CUCKOO_ROOT, whitelist_file), 'r') as f:
                  self.domain_whitelist += self.domain_whitelist + f.read().split("\n")
                  self.domain_whitelist = list(set(self.domain_whitelist))

        self.ip_whitelist = set()

    def _dns_gethostbyname(self, name):
        """Get host by name wrapper.
        @param name: hostname.
        @return: IP address or blank
        """
        if cfg.processing.resolve_dns:
            ip = resolve(name)
        else:
            ip = ""
        return ip

    def _is_private_ip(self, ip):
        """Check if the IP belongs to private network blocks.
        @param ip: IP address to verify.
        @return: boolean representing whether the IP belongs or not to
                 a private network block.
        """
        networks = [
            ("0.0.0.0", 8),
            ("10.0.0.0", 8),
            ("100.64.0.0", 10),
            ("127.0.0.0", 8),
            ("169.254.0.0", 16),
            ("172.16.0.0", 12),
            ("192.0.0.0", 24),
            ("192.0.2.0", 24),
            ("192.88.99.0", 24),
            ("192.168.0.0", 16),
            ("198.18.0.0", 15),
            ("198.51.100.0", 24),
            ("203.0.113.0", 24),
            ("240.0.0.0", 4),
            ("255.255.255.255", 32),
            ("224.0.0.0", 4)
        ]

        try:
            ipaddr = struct.unpack(">I", socket.inet_aton(ip))[0]
            for netaddr, bits in networks:
                network_low = struct.unpack(">I", socket.inet_aton(netaddr))[0]
                network_high = network_low | (1 << (32 - bits)) - 1
                if ipaddr <= network_high and ipaddr >= network_low:
                    return True
        except:
            pass

        return False

    def _get_cn(self, ip):
        cn = "unknown"
        log = logging.getLogger("Processing.Pcap")
        if IS_GEOIP:
            try:
                temp_cn = gi.country_name_by_addr(ip)
                if temp_cn:
                    cn = temp_cn
            except:
                log.error("Unable to GEOIP resolve %s" % ip)
        return cn

    def _add_hosts(self, connection):
        """Add IPs to unique list.
        @param connection: connection data
        """
        try:
            if connection["dst"] not in self.hosts:
                ip = convert_to_printable(connection["dst"])

                if ip not in self.hosts:
                    if ip in self.ip_whitelist:
                         return False
                    self.hosts.append(ip)

                    # We add external IPs to the list, only the first time
                    # we see them and if they're the destination of the
                    # first packet they appear in.
                    if not self._is_private_ip(ip):
                        self.unique_hosts.append(ip)
        except:
            pass

    def _enrich_hosts(self, unique_hosts):
        enriched_hosts = []

        if cfg.processing.reverse_dns:
            d = dns.resolver.Resolver()
            d.timeout = 5.0
            d.lifetime = 5.0

        while unique_hosts:
            ip = unique_hosts.pop()
            inaddrarpa = ""
            hostname = ""
            if cfg.processing.reverse_dns:
                try:
                    inaddrarpa = d.query(from_address(ip), "PTR").rrset[0].to_text()
                except:
                    pass
            for request in self.dns_requests.values():
                for answer in request['answers']:
                    if answer["data"] == ip:
                        hostname = request["request"]
                        break
                if hostname:
                    break

            enriched_hosts.append({"ip": ip, "country_name": self._get_cn(ip),
                                   "hostname": hostname, "inaddrarpa": inaddrarpa})
        return enriched_hosts

    def _tcp_dissect(self, conn, data):
        """Runs all TCP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        if self._check_http(data):
            self._add_http(conn, data)
        # SMTP.
        if conn["dport"] == 25 or conn["dport"] == 587:
            self._reassemble_smtp(conn, data)
        # IRC.
        if conn["dport"] != 21 and self._check_irc(data):
            self._add_irc(conn, data)
        # ja3
        ja3hash = self._check_ja3(data)
        if ja3hash != None:
            self._add_ja3(conn, data, ja3hash)

    def _udp_dissect(self, conn, data):
        """Runs all UDP dissectors.
        @param conn: connection.
        @param data: payload data.
        """
        # Select DNS and MDNS traffic.
        if conn["dport"] == 53 or conn["sport"] == 53 or conn["dport"] == 5353 or conn["sport"] == 5353:
            if self._check_dns(data):
                self._add_dns(data)

    def _check_icmp(self, icmp_data):
        """Checks for ICMP traffic.
        @param icmp_data: ICMP data flow.
        """
        try:
            return isinstance(icmp_data, dpkt.icmp.ICMP) and \
                   len(icmp_data.data) > 0
        except:
            return False

    def _icmp_dissect(self, conn, data):
        """Runs all ICMP dissectors.
        @param conn: connection.
        @param data: payload data.
        """

        if self._check_icmp(data):
            # If ICMP packets are coming from the host, it probably isn't
            # relevant traffic, hence we can skip from reporting it.
            if conn["src"] == cfg.resultserver.ip:
                return

            entry = {}
            entry["src"] = conn["src"]
            entry["dst"] = conn["dst"]
            entry["type"] = data.type

            # Extract data from dpkg.icmp.ICMP.
            try:
                entry["data"] = convert_to_printable(data.data.data)
            except:
                entry["data"] = ""

            self.icmp_requests.append(entry)

    def _check_dns(self, udpdata):
        """Checks for DNS traffic.
        @param udpdata: UDP data flow.
        """
        try:
            dpkt.dns.DNS(udpdata)
        except:
            return False

        return True

    def _add_dns(self, udpdata):
        """Adds a DNS data flow.
        @param udpdata: UDP data flow.
        """
        dns = dpkt.dns.DNS(udpdata)

        # DNS query parsing.
        query = {}

        if dns.rcode == dpkt.dns.DNS_RCODE_NOERR or \
                        dns.qr == dpkt.dns.DNS_R or \
                        dns.opcode == dpkt.dns.DNS_QUERY or True:
            # DNS question.
            try:
                q_name = dns.qd[0].name
                q_type = dns.qd[0].type
            except IndexError:
                return False

            query["request"] = q_name
            if q_type == dpkt.dns.DNS_A:
                query["type"] = "A"
            if q_type == dpkt.dns.DNS_AAAA:
                query["type"] = "AAAA"
            elif q_type == dpkt.dns.DNS_CNAME:
                query["type"] = "CNAME"
            elif q_type == dpkt.dns.DNS_MX:
                query["type"] = "MX"
            elif q_type == dpkt.dns.DNS_PTR:
                query["type"] = "PTR"
            elif q_type == dpkt.dns.DNS_NS:
                query["type"] = "NS"
            elif q_type == dpkt.dns.DNS_SOA:
                query["type"] = "SOA"
            elif q_type == dpkt.dns.DNS_HINFO:
                query["type"] = "HINFO"
            elif q_type == dpkt.dns.DNS_TXT:
                query["type"] = "TXT"
            elif q_type == dpkt.dns.DNS_SRV:
                query["type"] = "SRV"

            # DNS answer.
            query["answers"] = []
            for answer in dns.an:
                ans = {}
                if answer.type == dpkt.dns.DNS_A:
                    ans["type"] = "A"
                    try:
                        ans["data"] = socket.inet_ntoa(answer.rdata)
                    except socket.error:
                        continue
                elif answer.type == dpkt.dns.DNS_AAAA:
                    ans["type"] = "AAAA"
                    try:
                        ans["data"] = socket.inet_ntop(socket.AF_INET6,
                                                       answer.rdata)
                    except (socket.error, ValueError):
                        continue
                elif answer.type == dpkt.dns.DNS_CNAME:
                    ans["type"] = "CNAME"
                    ans["data"] = answer.cname
                elif answer.type == dpkt.dns.DNS_MX:
                    ans["type"] = "MX"
                    ans["data"] = answer.mxname
                elif answer.type == dpkt.dns.DNS_PTR:
                    ans["type"] = "PTR"
                    ans["data"] = answer.ptrname
                elif answer.type == dpkt.dns.DNS_NS:
                    ans["type"] = "NS"
                    ans["data"] = answer.nsname
                elif answer.type == dpkt.dns.DNS_SOA:
                    ans["type"] = "SOA"
                    ans["data"] = ",".join([answer.mname,
                                            answer.rname,
                                            str(answer.serial),
                                            str(answer.refresh),
                                            str(answer.retry),
                                            str(answer.expire),
                                            str(answer.minimum)])
                elif answer.type == dpkt.dns.DNS_HINFO:
                    ans["type"] = "HINFO"
                    ans["data"] = " ".join(answer.text)
                elif answer.type == dpkt.dns.DNS_TXT:
                    ans["type"] = "TXT"
                    ans["data"] = " ".join(answer.text)

                # TODO: add srv handling
                query["answers"].append(ans)

            if dns.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN:
                ans = {}
                ans["type"] = "NXDOMAIN"
                ans["data"] = ""
                query["answers"].append(ans)

            if enabled_whitelist:
                for reject in self.domain_whitelist:
                    if reject.startswith("#") or len(reject.strip()) == 0:
                        continue # comment or empty line
                    try:
                        if re.search(reject, query["request"]):
                            if query["answers"]:
                                for addip in query["answers"]:
                                    if addip["type"] == "A" or addip["type"] == "AAAA":
                                         self.ip_whitelist.add(addip["data"])
                            return True
                    except re.RegexError as e:
                        log.error(("bad regex", reject, e))

            self._add_domain(query["request"])

            reqtuple = query["type"], query["request"]
            if reqtuple not in self.dns_requests:
                self.dns_requests[reqtuple] = query
            new_answers = set((i["type"], i["data"]) for i in query["answers"]) - self.dns_answers
            self.dns_answers.update(new_answers)
            self.dns_requests[reqtuple]["answers"] += [dict(type=i[0], data=i[1]) for i in new_answers]

        return True

    def _add_domain(self, domain):
        """Add a domain to unique list.
        @param domain: domain name.
        """
        filters = [
            ".*\\.windows\\.com$",
            ".*\\.in\\-addr\\.arpa$",
            ".*\\.ip6\\.arpa$"
        ]

        regexps = [re.compile(filter) for filter in filters]
        for regexp in regexps:
            if regexp.match(domain):
                return

        for entry in self.unique_domains:
            if entry["domain"] == domain:
                return

        self.unique_domains.append({"domain": domain,
                                    "ip": self._dns_gethostbyname(domain)})

    def _check_http(self, tcpdata):
        """Checks for HTTP traffic.
        @param tcpdata: TCP data flow.
        """
        try:
            r = dpkt.http.Request()
            r.method, r.version, r.uri = None, None, None
            r.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            if r.method is not None or r.version is not None or \
                            r.uri is not None:
                return True
            return False

        return True

    def _add_http(self, conn, tcpdata):
        """Adds an HTTP flow.
        @param conn: TCP connection info.
        @param tcpdata: TCP data flow.
        """
        if tcpdata in self.http_requests:
            self.http_requests[tcpdata]["count"] += 1
            return True

        try:
            http = dpkt.http.Request()
            http.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            pass

        try:
            entry = {"count": 1}

            if "host" in http.headers and re.match(
                    '^([A-Z0-9]|[A-Z0-9][A-Z0-9\-]{0,61}[A-Z0-9])(\.([A-Z0-9]|[A-Z0-9][A-Z0-9\-]{0,61}[A-Z0-9]))+(:[0-9]{1,5})?$',
                    http.headers["host"], re.IGNORECASE):
                entry["host"] = convert_to_printable(http.headers["host"])
            else:
                entry["host"] = conn["dst"]

            if enabled_whitelist:
                for reject in self.domain_whitelist:
                    # comment or empty line
                    if reject.startswith("#") or len(reject.strip()) == 0:
                        continue
                    if re.search(reject, entry["host"]):
                        return False

            entry["port"] = conn["dport"]

            # Manually deal with cases when destination port is not the default one,
            # and it is  not included in host header.
            netloc = entry["host"]
            if entry["port"] != 80 and ":" not in netloc:
                netloc += ":" + str(entry["port"])

            entry["data"] = convert_to_printable(tcpdata)
            entry["uri"] = convert_to_printable(
                urlunparse(("http", netloc, http.uri, None, None, None)))
            entry["body"] = convert_to_printable(http.body)
            entry["path"] = convert_to_printable(http.uri)

            if "user-agent" in http.headers:
                entry["user-agent"] = \
                    convert_to_printable(http.headers["user-agent"])
            else:
                entry["user-agent"] = ""

            entry["version"] = convert_to_printable(http.version)
            entry["method"] = convert_to_printable(http.method)

            self.http_requests[tcpdata] = entry
        except Exception:
            return False

        return True

    def _reassemble_smtp(self, conn, data):
        """Reassemble a SMTP flow.
        @param conn: connection dict.
        @param data: raw data.
        """
        if conn["dst"] in self.smtp_flow:
            self.smtp_flow[conn["dst"]] += data
        else:
            self.smtp_flow[conn["dst"]] = data

    def _process_smtp(self):
        """Process SMTP flow."""
        for conn, data in six.iteritems(self.smtp_flow):
            # Detect new SMTP flow.
            if data.startswith((b"EHLO", b"HELO")):
                self.smtp_requests.append({"dst": conn,
                                           "raw": convert_to_printable(data)})

    def _check_irc(self, tcpdata):
        """
        Checks for IRC traffic.
        @param tcpdata: tcp data flow
        """
        try:
            req = ircMessage()
        except Exception:
            return False

        return req.isthereIRC(tcpdata)

    def _add_irc(self, conn, tcpdata):
        """
        Adds an IRC communication.
	    @param conn: TCP connection info.
        @param tcpdata: TCP data in flow
        """

        if enabled_whitelist:
            if conn["src"] in self.ip_whitelist:
                 return False
            if conn["dst"] in self.ip_whitelist:
                 return False

        try:
            reqc = ircMessage()
            reqs = ircMessage()
            filters_sc = ["266"]
            client = reqc.getClientMessages(tcpdata)
            for message in client:
                message.update(conn)
            server = reqs.getServerMessagesFilter(tcpdata, filters_sc)
            for message in server:
                message.update(conn)
            self.irc_requests = self.irc_requests + \
                                client + \
                                server
        except Exception:
            return False

        return True

    def _check_ja3(self, tcpdata):
        """Generate JA3 fingerprint for TLS HELLO
        Based on and importing from https://github.com/salesforce/ja3
        @param tcpdata: TCP data flow.
        """

        tls_handshake = bytearray(tcpdata)
        if tls_handshake[0] != TLS_HANDSHAKE:
            return

        records = list()
        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcpdata)
        except dpkt.ssl.SSL3Exception:
            return
        except dpkt.dpkt.NeedData:
            return

        if len(records) <= 0:
            return

        for record in records:
            if record.type != TLS_HANDSHAKE:
                return
            if len(record.data) == 0:
                return
            client_hello = bytearray(record.data)
            if client_hello[0] != 1:
                # We only want client HELLO
                return
            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData:
                # Looking for a handshake here
                return
            if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                # Still not the HELLO
                return

            client_handshake = handshake.data
            buf, ptr = parse_variable_array(client_handshake.data, 1)
            buf, ptr = parse_variable_array(client_handshake.data[ptr:], 2)
            ja3 = [str(client_handshake.version)]

            # Cipher Suites (16 bit values)
            ja3.append(convert_to_ja3_segment(buf, 2))
            ja3 += process_extensions(client_handshake)
            ja3 = ",".join(ja3)

            return md5(ja3.encode()).hexdigest()

    def _add_ja3(self, conn, tcpdata, ja3hash):
        """
        Adds an JA3 digest.
	    @param conn: TCP connection info.
        @param tcpdata: TCP data in flow
        """
        if conn["src"] == cfg.resultserver.ip:
            return

        entry = {}
        entry["src"] = conn["src"]
        entry["sport"] = conn["sport"]
        entry["dst"] = conn["dst"]
        entry["dport"] = conn["dport"]
        entry["ja3"] = ja3hash
        entry["desc"] = "unknown"

        if ja3hash in self.ja3_fprints:
            entry["desc"] = self.ja3_fprints[ja3hash]

        self.ja3_records.append(entry)

    def run(self):
        """Process PCAP.
        @return: dict with network analysis data.
        """
        log = logging.getLogger("Processing.Pcap")
        """
        #this should be configurable
        missed_urls = list()
        #https://github.com/kevoreilly/capemon/blob/capemon/hook_network.c
        missed_urls_apis = (
            "HttpOpenRequestA",  # hConnect?
            "HttpOpenRequestW",  # hConnect?
            "InternetConnectA",  #  ServerName, ServerPort
            "InternetConnectW",  #  ServerName, ServerPort
            "HttpSendRequestA",  # Headers: Referer: http://124.150.175.133/sbrQn0ueq8/EhJiZIoBi/jBRna68dNx/L8sAZQMt43z1zh4/SeMGBbEWdtoOs/ Content-Type: multipart/form-data;
            "HttpSendRequestW",  # Headers: Referer: http://124.150.175.133/sbrQn0ueq8/EhJiZIoBi/jBRna68dNx/L8sAZQMt43z1zh4/SeMGBbEWdtoOs/ Content-Type: multipart/form-data;
            "InternetOpenUrlA",  # URL
            "InternetOpenUrlW",  # URL
            "URLDownloadToCacheFileA",  # URL
            "URLDownloadToCacheFileW",  # URL
            #HttpSendRequestExW
            #HttpSendRequestExA
            "InternetCrackUrlA", #URL
            "InternetCrackUrlW", #URL
        )

        for proc in self.results["behavior"]["processes"]:
            for call in proc["calls"]:
                if call.get("api", "") in missed_urls_apis:

        """
        if not IS_DPKT:
            log.error("Python DPKT is not installed, aborting PCAP analysis.")
            return self.results

        if not os.path.exists(self.filepath):
            log.warning("The PCAP file does not exist at path \"%s\".", self.filepath)
            return self.results

        if os.path.getsize(self.filepath) == 0:
            log.error("The PCAP file at path \"%s\" is empty." % self.filepath)
            return self.results

        try:
            file = open(self.filepath, "rb")
        except (IOError, OSError):
            log.error("Unable to open %s" % self.filepath)
            return self.results

        try:
            pcap = dpkt.pcap.Reader(file)
        except dpkt.dpkt.NeedData:
            log.error("Unable to read PCAP file at path \"%s\".",
                      self.filepath)
            return self.results
        except ValueError:
            log.error("Unable to read PCAP file at path \"%s\". File is "
                      "corrupted or wrong format." % self.filepath)
            return self.results

        offset = file.tell()
        first_ts = None
        for ts, buf in pcap:
            if not first_ts:
                first_ts = ts

            try:
                ip = iplayer_from_raw(buf, pcap.datalink())

                connection = {}
                if isinstance(ip, dpkt.ip.IP):
                    connection["src"] = socket.inet_ntoa(ip.src)
                    connection["dst"] = socket.inet_ntoa(ip.dst)
                elif isinstance(ip, dpkt.ip6.IP6):
                    connection["src"] = socket.inet_ntop(socket.AF_INET6,
                                                         ip.src)
                    connection["dst"] = socket.inet_ntop(socket.AF_INET6,
                                                         ip.dst)
                else:
                    offset = file.tell()
                    continue

                self._add_hosts(connection)

                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    if not isinstance(tcp, dpkt.tcp.TCP):
                        try:
                            tcp = dpkt.tcp.TCP(tcp)
                        except dpkt.UnpackError:
                            continue

                    connection["sport"] = tcp.sport
                    connection["dport"] = tcp.dport
                    if len(tcp.data) > 0:
                        self._tcp_dissect(connection, tcp.data)

                    src, sport, dst, dport = (
                        connection["src"], connection["sport"], connection["dst"], connection["dport"])
                    if not ((dst, dport, src, sport) in self.tcp_connections_seen or (
                             src, sport, dst, dport) in self.tcp_connections_seen):
                        self.tcp_connections.append((src, sport, dst, dport, offset, ts - first_ts))
                        self.tcp_connections_seen.add((src, sport, dst, dport))

                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    udp = ip.data
                    if not isinstance(udp, dpkt.udp.UDP):
                        udp = dpkt.udp.UDP(udp)

                    connection["sport"] = udp.sport
                    connection["dport"] = udp.dport
                    if len(udp.data) > 0:
                        self._udp_dissect(connection, udp.data)

                    src, sport, dst, dport = (
                        connection["src"], connection["sport"], connection["dst"], connection["dport"])
                    if not ((dst, dport, src, sport) in self.udp_connections_seen or (
                             src, sport, dst, dport) in self.udp_connections_seen):
                        self.udp_connections.append((src, sport, dst, dport, offset, ts - first_ts))
                        self.udp_connections_seen.add((src, sport, dst, dport))

                elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                    icmp = ip.data
                    if not isinstance(icmp, dpkt.icmp.ICMP):
                        icmp = dpkt.icmp.ICMP(icmp)

                    self._icmp_dissect(connection, icmp)

                offset = file.tell()
            except AttributeError:
                continue
            except dpkt.dpkt.NeedData:
                continue
            except Exception as e:
                log.exception("Failed to process packet: %s", e)

        file.close()

        # Post processors for reconstructed flows.
        self._process_smtp()

        # Remove hosts that have an IP which correlate to a whitelisted domain

        # Build results dict.
        self.results["hosts"] = self._enrich_hosts(self.unique_hosts)
        self.results["domains"] = self.unique_domains
        self.results["tcp"] = [conn_from_flowtuple(i) for i in self.tcp_connections]
        self.results["udp"] = [conn_from_flowtuple(i) for i in self.udp_connections]
        self.results["icmp"] = self.icmp_requests
        self.results["http"] = list(self.http_requests.values())
        self.results["dns"] = list(self.dns_requests.values())
        self.results["smtp"] = self.smtp_requests
        self.results["irc"] = self.irc_requests
        self.results["ja3"] = self.ja3_records

        if enabled_whitelist:

            for host in self.results["hosts"]:
                for delip in self.ip_whitelist:
                    if delip == host["ip"]:
                        self.results["hosts"].remove(host)

            for keyword in ("tcp", "udp", "icmp"):
                for host in self.results[keyword]:
                    for delip in self.ip_whitelist:
                        if delip == host["src"] or delip == host["dst"]:
                            self.results[keyword].remove(host)

        return self.results


class NetworkAnalysis(Processing):
    """Network analysis."""

    def _import_ja3_fprints(self):
        """
        open and read ja3 fingerprint json file from:
        https://github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json
        :return: dictionary of ja3 fingerprint descreptions
        """
        ja3_fprints = {}
        if os.path.exists(self.ja3_file):
            with open(self.ja3_file, 'r') as fpfile:
                for line in fpfile:
                    try:
                        ja3 = (loads(line))
                        if "ja3_hash" in ja3 and 'desc' in ja3:
                            ja3_fprints[ja3['ja3_hash']] = ja3['desc']
                    except Exception as e:
                        pass

        return ja3_fprints

    def run(self):
        self.key = "network"
        self.ja3_file = self.options.get("ja3_file", os.path.join(CUCKOO_ROOT, "data", "ja3", "ja3fingerprint.json"))
        if not IS_DPKT:
            log.error("Python DPKT is not installed, aborting PCAP analysis.")
            return {}

        if not os.path.exists(self.pcap_path):
            log.warning("The PCAP file does not exist at path \"%s\".",
                        self.pcap_path)
            return {}

        if os.path.getsize(self.pcap_path) == 0:
            log.error("The PCAP file at path \"%s\" is empty." % self.pcap_path)
            return {}

        ja3_fprints = self._import_ja3_fprints()

        sorted_path = self.pcap_path.replace("dump.", "dump_sorted.")
        if cfg.processing.sort_pcap:
            sort_pcap(self.pcap_path, sorted_path)
            buf = Pcap(self.pcap_path, ja3_fprints).run()
            results = Pcap(sorted_path, ja3_fprints).run()
            results["http"] = buf["http"]
            results["dns"] = buf["dns"]
        else:
            results = Pcap(self.pcap_path, ja3_fprints).run()

        # Save PCAP file hash.
        if os.path.exists(self.pcap_path):
            results["pcap_sha256"] = File(self.pcap_path).get_sha256()
        if os.path.exists(sorted_path):
            results["sorted_pcap_sha256"] = File(sorted_path).get_sha256()

        return results


def iplayer_from_raw(raw, linktype=1):
    """Converts a raw packet to a dpkt packet regarding of link type.
    @param raw: raw packet
    @param linktype: integer describing link type as expected by dpkt
    """
    if linktype == 1:  # ethernet
        pkt = dpkt.ethernet.Ethernet(raw)
        ip = pkt.data
    elif linktype == 101:  # raw
        ip = dpkt.ip.IP(raw)
    else:
        raise CuckooProcessingError("unknown PCAP linktype")
    return ip


def conn_from_flowtuple(ft):
    """Convert the flow tuple into a dictionary (suitable for JSON)"""
    sip, sport, dip, dport, offset, relts = ft
    return {"src": sip, "sport": sport,
            "dst": dip, "dport": dport,
            "offset": offset, "time": relts}


# input_iterator should be a class that also supports writing so we can use
# it for the temp files
# this code is mostly taken from some SO post, can't remember the url though
def batch_sort(input_iterator, output_path, buffer_size=32000, output_class=None):
    """batch sort helper with temporary files, supports sorting large stuff"""
    if not output_class:
        output_class = input_iterator.__class__

    chunks = []
    try:
        while True:
            current_chunk = list(islice(input_iterator, buffer_size))
            if not current_chunk:
                break
            current_chunk.sort()
            fd, filepath = tempfile.mkstemp()
            os.close(fd)
            output_chunk = output_class(filepath)
            chunks.append(output_chunk)

            for elem in current_chunk:
                output_chunk.write(elem.obj)
            output_chunk.close()

        output_file = output_class(output_path)
        for elem in heapq.merge(*chunks):
            output_file.write(elem.obj)
        else:
            output_file.write()
        output_file.close()
    finally:
        for chunk in chunks:
            try:
                chunk.close()
                os.remove(chunk.name)
            except Exception:
                pass


# magic
class SortCap(object):
    """SortCap is a wrapper around the packet lib (dpkt) that allows us to sort pcaps
    together with the batch_sort function above."""

    def __init__(self, path, linktype=1):
        self.name = path
        self.linktype = linktype
        self.fileobj = None
        self.fd = None
        self.ctr = 0  # counter to pass through packets without flow info (non-IP)
        self.conns = set()

    def write(self, p=None):
        if not self.fileobj:
            self.fileobj = open(self.name, "wb")
            self.fd = dpkt.pcap.Writer(self.fileobj, linktype=self.linktype)
        if p:
            self.fd.writepkt(p.raw, p.ts)

    def __iter__(self):
        if not self.fileobj:
            self.fileobj = open(self.name, "rb")
            self.fd = dpkt.pcap.Reader(self.fileobj)
            self.fditer = iter(self.fd)
            self.linktype = self.fd.datalink()
        return self

    def close(self):
        if self.fileobj:
            self.fileobj.close()
        self.fd = None
        self.fileobj = None

    def __next__(self):
        rp = next(self.fditer)
        if rp is None:
            return None
        self.ctr += 1

        ts, raw = rp
        rpkt = Packet(raw, ts)

        sip, dip, sport, dport, proto = flowtuple_from_raw(raw, self.linktype)

        # check other direction of same flow
        if (dip, sip, dport, sport, proto) in self.conns:
            flowtuple = (dip, sip, dport, sport, proto)
        else:
            flowtuple = (sip, dip, sport, dport, proto)

        self.conns.add(flowtuple)
        return Keyed((flowtuple, ts, self.ctr), rpkt)


def sort_pcap(inpath, outpath):
    """Use SortCap class together with batch_sort to sort a pcap"""
    inc = SortCap(inpath)
    batch_sort(inc, outpath, output_class=lambda path: SortCap(path, linktype=inc.linktype))
    return 0


def flowtuple_from_raw(raw, linktype=1):
    """Parse a packet from a pcap just enough to gain a flow description tuple"""
    ip = iplayer_from_raw(raw, linktype)

    if isinstance(ip, dpkt.ip.IP):
        sip, dip = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        proto = ip.p
        l3 = ip.data

        if proto == dpkt.ip.IP_PROTO_TCP and isinstance(l3, dpkt.tcp.TCP):
            sport, dport = l3.sport, l3.dport

        elif proto == dpkt.ip.IP_PROTO_UDP and isinstance(l3, dpkt.udp.UDP):
            sport, dport = l3.sport, l3.dport

        else:
            sport, dport = 0, 0

    else:
        sip, dip, proto = 0, 0, -1
        sport, dport = 0, 0

    flowtuple = (sip, dip, sport, dport, proto)
    return flowtuple


def payload_from_raw(raw, linktype=1):
    """Get the payload from a packet, the data below TCP/UDP basically"""
    ip = iplayer_from_raw(raw, linktype)
    try:
        return ip.data.data
    except:
        return ""


def next_connection_packets(piter, linktype=1):
    """Extract all packets belonging to the same flow from a pcap packet iterator"""
    first_ft = None

    for ts, raw in piter:
        ft = flowtuple_from_raw(raw, linktype)
        if not first_ft:
            first_ft = ft

        sip, dip, sport, dport, proto = ft
        if not (first_ft == ft or first_ft == (dip, sip, dport, sport, proto)):
            break

        yield {
            "src": sip, "dst": dip, "sport": sport, "dport": dport,
            "raw": b64encode(payload_from_raw(raw, linktype)).decode("utf-8"),
            "direction": first_ft == ft,
        }


def packets_for_stream(fobj, offset):
    """Open a PCAP, seek to a packet offset, then get all packets belonging to the same connection"""
    pcap = dpkt.pcap.Reader(fobj)
    pcapiter = iter(pcap)
    ts, raw = next(pcapiter)

    fobj.seek(offset)
    for p in next_connection_packets(pcapiter, linktype=pcap.datalink()):
        yield p
