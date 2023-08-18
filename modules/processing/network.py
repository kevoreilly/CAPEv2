# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# Imports for the batch sort.
# http://stackoverflow.com/questions/10665925/how-to-sort-huge-files-with-python
# http://code.activestate.com/recipes/576755/

import binascii
import heapq
import logging
import os
import socket
import struct
import sys
import tempfile
import traceback
from base64 import b64encode
from collections import OrderedDict, namedtuple
from contextlib import suppress
from hashlib import md5, sha1, sha256
from itertools import islice
from json import loads
from urllib.parse import urlunparse

import cachetools.func
import dns.resolver
from dns.reversename import from_address

from data.safelist.domains import domain_passlist_re
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.dns import resolve
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.irc import ircMessage
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_mkdir, path_read_file, path_write_file
from lib.cuckoo.common.safelist import is_safelisted_domain
from lib.cuckoo.common.utils import convert_to_printable

# from lib.cuckoo.common.safelist import is_safelisted_ip

try:
    import re2 as re
except ImportError:
    import re


HAVE_GEOIP = False
with suppress(ImportError):
    import maxminddb

    HAVE_GEOIP = True

try:
    import dpkt

    IS_DPKT = True
except ImportError:
    IS_DPKT = False
    print("Missed dependency: pip3 install -U dpkt")

HAVE_HTTPREPLAY = False
try:
    import httpreplay
    import httpreplay.cut

    if httpreplay.__version__ == "0.3":
        HAVE_HTTPREPLAY = True
except ImportError:
    print("OPTIONAL! Missed dependency: poetry run pip install -U git+https://github.com/CAPESandbox/httpreplay")
except SystemError as e:
    print("httpreplay: %s", str(e))

# required to work webgui
CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..")
sys.path.append(CUCKOO_ROOT)

TLS_HANDSHAKE = 22

Keyed = namedtuple("Keyed", ["key", "obj"])
Packet = namedtuple("Packet", ["raw", "ts"])

log = logging.getLogger(__name__)
cfg = Config()
proc_cfg = Config("processing")
enabled_passlist = proc_cfg.network.dnswhitelist
passlist_file = proc_cfg.network.dnswhitelist_file

enabled_ip_passlist = proc_cfg.network.ipwhitelist
ip_passlist_file = proc_cfg.network.ipwhitelist_file

# Be less verbose about httpreplay logging messages.
logging.getLogger("httpreplay").setLevel(logging.CRITICAL)

comment_re = re.compile(r"\s*#.*")
if enabled_passlist and passlist_file:
    f = path_read_file(os.path.join(CUCKOO_ROOT, passlist_file), mode="text")
    for domain in f.splitlines():
        domain = comment_re.sub("", domain).strip()
        if domain:
            domain_passlist_re.append(domain)

ip_passlist = set()
if enabled_ip_passlist and ip_passlist_file:
    f = path_read_file(os.path.join(CUCKOO_ROOT, ip_passlist_file), mode="text")
    for ip in f.splitlines():
        ip = comment_re.sub("", ip).strip()
        if ip:
            ip_passlist.add(ip)

if HAVE_GEOIP and proc_cfg.network.maxmind_database:
    # Reload the maxmind database when it has changed, but only check the file system
    # every 5 minutes.
    _MAXMINDDB_PATH = os.path.join(CUCKOO_ROOT, proc_cfg.network.maxmind_database)
    _MAXMINDDB_CLIENT = None
    _MAXMINDDB_MTIME = None

    @cachetools.func.ttl_cache(maxsize=None, ttl=5 * 60)
    def get_maxminddb_client():
        global _MAXMINDDB_CLIENT
        global _MAXMINDDB_MTIME
        if path_exists(_MAXMINDDB_PATH):
            mtime = os.stat(_MAXMINDDB_PATH).st_mtime
            if mtime != _MAXMINDDB_MTIME:
                _MAXMINDDB_MTIME = mtime
                log.info("Loading maxmind database from %s", _MAXMINDDB_PATH)
                _MAXMINDDB_CLIENT = maxminddb.open_database(_MAXMINDDB_PATH)
            return _MAXMINDDB_CLIENT
        return None

else:

    def get_maxminddb_client():
        return None


class Pcap:
    """Reads network data from PCAP file."""

    ssl_ports = (443,)

    def __init__(self, filepath, ja3_fprints, options):
        """Creates a new instance.
        @param filepath: path to PCAP file
        """
        self.filepath = filepath
        self.ja3_fprints = ja3_fprints
        self.options = options

        # List of all hosts.
        self.hosts = []
        # List containing all non-private IP addresses.
        self.unique_hosts = []
        # List of unique domains.
        self.unique_domains = []
        # List containing all TCP packets.
        self.tcp_connections = []
        self.tcp_connections_seen = set()
        # Lookup table to identify connection requests to services or IP
        # addresses that are no longer available.
        self.tcp_connections_dead = {}
        self.dead_hosts = {}
        self.alive_hosts = {}
        # List containing all UDP packets.
        self.udp_connections = []
        self.udp_connections_seen = set()
        # List containing all ICMP requests.
        self.icmp_requests = []
        # List containing all HTTP requests.
        self.http_requests = OrderedDict()
        # List containing all TLS/SSL3 key combinations.
        self.tls_keys = []
        # List containing all DNS requests.
        self.dns_requests = OrderedDict()
        self.dns_answers = set()
        # List of known good DNS servers
        self.known_dns = self._build_known_dns()
        # List of all used DNS servers
        self.dns_servers = []
        # List containing all SMTP requests.
        self.smtp_requests = []
        # Reconstruncted SMTP flow.
        self.smtp_flow = {}
        # List containing all IRC requests.
        self.irc_requests = []
        # Dictionary containing all the results of this processing.
        self.results = {}
        # DNS ignore list
        self.safelist_enabled = self.options.get("safelist_dns")

    def _is_safelisted(self, conn, hostname):
        """Check if safelisting conditions are met"""
        # Is safelistng enabled?
        if not self.safelist_enabled:
            return False

        # Is DNS recording coming from allowed NS server.
        if conn.get("src") not in self.known_dns and conn.get("dst") not in self.known_dns:
            return False

        # Is hostname safelisted.
        if not is_safelisted_domain(hostname):
            return False

        return True

    def _build_known_dns(self):
        """Build known DNS list."""
        _known_dns = self.options.get("allowed_dns")
        if _known_dns is not None:
            return [r.strip() for r in _known_dns.split(",")]
        return []

    def _dns_gethostbyname(self, name):
        """Get host by name wrapper.
        @param name: hostname.
        @return: IP address or blank
        """
        return resolve(name) if cfg.processing.resolve_dns else ""

    def _is_private_ip(self, ip):
        """Check if the IP belongs to private network blocks.
        @param ip: IP address to verify.
        @return: boolean representing whether the IP belongs or not to
                 a private network block.
        """
        networks = (
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
            ("224.0.0.0", 4),
        )

        with suppress(Exception):
            ipaddr = struct.unpack(">I", socket.inet_aton(ip))[0]
            for netaddr, bits in networks:
                network_low = struct.unpack(">I", socket.inet_aton(netaddr))[0]
                network_high = network_low | (1 << (32 - bits)) - 1
                if ipaddr <= network_high and ipaddr >= network_low:
                    return True

    def _get_cn(self, ip):
        if proc_cfg.network.country_lookup:
            maxminddb_client = get_maxminddb_client()
            if maxminddb_client:
                try:
                    return maxminddb_client.get(ip).get("country", {}).get("names", {}).get("en", "unknown")
                except Exception:
                    log.error("Unable to resolve GEOIP for %s", ip)
        return "unknown"

    def _add_hosts(self, connection):
        """Add IPs to unique list.
        @param connection: connection data
        """
        with suppress(Exception):
            if connection["dst"] not in self.hosts:
                ip = convert_to_printable(connection["dst"])

                if ip not in self.hosts:
                    if ip in ip_passlist:
                        return False
                    self.hosts.append(ip)

                    # We add external IPs to the list, only the first time
                    # we see them and if they're the destination of the
                    # first packet they appear in.
                    if not self._is_private_ip(ip):
                        self.unique_hosts.append(ip)

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
                with suppress(Exception):
                    inaddrarpa = d.query(from_address(ip), "PTR").rrset[0].to_text()
            for request in self.dns_requests.values():
                for answer in request["answers"]:
                    if answer["data"] == ip:
                        hostname = request["request"]
                        break
                if hostname:
                    break

            enriched_hosts.append({"ip": ip, "country_name": self._get_cn(ip), "hostname": hostname, "inaddrarpa": inaddrarpa})
        return enriched_hosts

    def _tcp_dissect(self, conn, data, ts):
        """Runs all TCP dissectors.
        @param conn: connection.
        @param data: payload data.
        @param ts: timestamp.
        """
        if self._check_http(data):
            self._add_http(conn, data, ts)
        # SMTP.
        if conn["dport"] in (25, 587):
            self._reassemble_smtp(conn, data)
        # IRC.
        if conn["dport"] != 21 and self._check_irc(data):
            self._add_irc(conn, data)
        # HTTPS.
        if conn["dport"] in self.ssl_ports or conn["sport"] in self.ssl_ports:
            self._https_identify(conn, data)

    def _udp_dissect(self, conn, data, ts):
        """Runs all UDP dissectors.
        @param conn: connection.
        @param data: payload data.
        @param ts: timestamp.
        """
        # Select DNS and MDNS traffic.
        if (conn["dport"] in (53, 5353) or conn["sport"] in (53, 5353)) and self._check_dns(data):
            self._add_dns(data, ts)

    def _check_icmp(self, icmp_data):
        """Checks for ICMP traffic.
        @param icmp_data: ICMP data flow.
        """
        try:
            return isinstance(icmp_data, dpkt.icmp.ICMP) and len(icmp_data.data) > 0
        except Exception:
            return False

    def _icmp_dissect(self, conn, data):
        """Runs all ICMP dissectors.
        @param conn: connection.
        @param data: payload data.
        """

        if not self._check_icmp(data):
            return

        # If ICMP packets are coming from the host, it probably isn't
        # relevant traffic, hence we can skip from reporting it.
        if conn["src"] == cfg.resultserver.ip:
            return

        entry = {"src": conn["src"], "dst": conn["dst"], "type": data.type}
        # Extract data from dpkg.icmp.ICMP.
        try:
            entry["data"] = convert_to_printable(data.data.data)
        except Exception:
            entry["data"] = ""

        self.icmp_requests.append(entry)

    def _check_dns(self, udpdata):
        """Checks for DNS traffic.
        @param udpdata: UDP data flow.
        """
        try:
            dpkt.dns.DNS(udpdata)
        except Exception:
            return False

        return True

    def _add_dns(self, udpdata, ts):
        """Adds a DNS data flow.
        @param udpdata: UDP data flow.
        @param ts: timestamp.
        """
        dns = dpkt.dns.DNS(udpdata)

        # DNS query parsing.
        query = {}

        if dns.rcode == dpkt.dns.DNS_RCODE_NOERR or dns.qr == dpkt.dns.DNS_R or dns.opcode == dpkt.dns.DNS_QUERY:
            # DNS question.
            try:
                q_name = dns.qd[0].name
                q_type = dns.qd[0].type
            except IndexError:
                return False

            query["request"] = q_name

            # See https://dpkt.readthedocs.io/en/latest/_modules/dpkt/dns.html
            type_mapping = {
                dpkt.dns.DNS_A: "A",
                dpkt.dns.DNS_NS: "NS",
                dpkt.dns.DNS_CNAME: "CNAME",
                dpkt.dns.DNS_SOA: "SOA",
                dpkt.dns.DNS_NULL: "NULL",
                dpkt.dns.DNS_PTR: "PTR",
                dpkt.dns.DNS_HINFO: "HINFO",
                dpkt.dns.DNS_MX: "MX",
                dpkt.dns.DNS_TXT: "TXT",
                dpkt.dns.DNS_AAAA: "AAAA",
                dpkt.dns.DNS_SRV: "SRV",
                dpkt.dns.DNS_OPT: "OPT",
            }
            if q_type in type_mapping:
                query["type"] = type_mapping[q_type]

            # DNS answer.
            query["answers"] = []
            for answer in dns.an:
                ans = {}
                if answer.type == dpkt.dns.DNS_A:
                    ans = {"type": "A"}
                    try:
                        ans["data"] = socket.inet_ntoa(answer.rdata)
                    except socket.error:
                        continue
                elif answer.type == dpkt.dns.DNS_AAAA:
                    ans = {"type": "AAAA"}
                    try:
                        ans["data"] = socket.inet_ntop(socket.AF_INET6, answer.rdata)
                    except (socket.error, ValueError):
                        continue
                elif answer.type == dpkt.dns.DNS_CNAME:
                    ans = {"type": "CNAME", "data": answer.cname}
                elif answer.type == dpkt.dns.DNS_MX:
                    ans = {"type": "MX", "data": answer.mxname}
                elif answer.type == dpkt.dns.DNS_PTR:
                    ans = {"type": "PTR", "data": answer.ptrname}
                elif answer.type == dpkt.dns.DNS_NS:
                    ans = {"type": "NS", "data": answer.nsname}
                elif answer.type == dpkt.dns.DNS_SOA:
                    ans = {
                        "type": "SOA",
                        "data": ",".join(
                            [
                                answer.mname,
                                answer.rname,
                                str(answer.serial),
                                str(answer.refresh),
                                str(answer.retry),
                                str(answer.expire),
                                str(answer.minimum),
                            ]
                        ),
                    }
                elif answer.type == dpkt.dns.DNS_HINFO:
                    ans = {"type": "HINFO", "data": " ".join(answer.text)}
                elif answer.type == dpkt.dns.DNS_TXT:
                    ans = {"type": "TXT", "data": " ".join(answer.text)}

                # TODO: add srv handling
                query["answers"].append(ans)

            if dns.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN:
                ans = {"type": "NXDOMAIN", "data": ""}
                query["answers"].append(ans)

            if enabled_passlist:
                for reject in domain_passlist_re:
                    if re.search(reject, query["request"]):
                        for addip in query["answers"]:
                            if addip["type"] in ("A", "AAAA"):
                                ip_passlist.add(addip["data"])
                        return True

            self._add_domain(query["request"])

            if "type" in query:
                reqtuple = query["type"], query["request"]
                if reqtuple not in self.dns_requests:
                    self.dns_requests[reqtuple] = query
                new_answers = {(i["type"], i["data"]) for i in query["answers"]} - self.dns_answers

                self.dns_answers.update(new_answers)
                self.dns_requests[reqtuple]["answers"].extend({"type": i[0], "data": i[1]} for i in new_answers)

                if "first_seen" not in self.dns_requests[reqtuple]:
                    self.dns_requests[reqtuple]["first_seen"] = ts
        return True

    def _add_domain(self, domain):
        """Add a domain to unique list.
        @param domain: domain name.
        """
        filters = (".*\\.windows\\.com$", ".*\\.in\\-addr\\.arpa$", ".*\\.ip6\\.arpa$")

        regexps = [re.compile(filter) for filter in filters]
        for regexp in regexps:
            if regexp.match(domain):
                return

        for entry in self.unique_domains:
            if entry["domain"] == domain:
                return

        self.unique_domains.append({"domain": domain, "ip": self._dns_gethostbyname(domain)})

    def _check_http(self, tcpdata):
        """Checks for HTTP traffic.
        @param tcpdata: TCP data flow.
        """
        try:
            r = dpkt.http.Request()
            r.method, r.version, r.uri = None, None, None
            r.unpack(tcpdata)
        except dpkt.dpkt.UnpackError:
            if r.method is not None or r.version is not None or r.uri is not None:
                return True
            return False

        return True

    def _add_http(self, conn, tcpdata, ts):
        """Adds an HTTP flow.
        @param conn: TCP connection info.
        @param tcpdata: TCP data flow.
        @param ts: timestamp.
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
                r"^([A-Z0-9]|[A-Z0-9][A-Z0-9\-]{0,61}[A-Z0-9])(\.([A-Z0-9]|[A-Z0-9][A-Z0-9\-]{0,61}[A-Z0-9]))+(:[0-9]{1,5})?$",
                http.headers["host"],
                re.IGNORECASE,
            ):
                entry["host"] = convert_to_printable(http.headers["host"])
            else:
                entry["host"] = conn["dst"]

            if enabled_passlist:
                for reject in domain_passlist_re:
                    if re.search(reject, entry["host"]):
                        return False

            entry["port"] = conn["dport"]

            # Manually deal with cases when destination port is not the default one,
            # and it is not included in host header.
            netloc = entry["host"]
            if entry["port"] != 80 and ":" not in netloc:
                netloc += f":{entry['port']}"

            # Sometimes the host is found inside the path in the HTTP headers. When that happens, parse the host outside of the path.
            path = http.uri
            if netloc and netloc in http.uri:
                path = http.uri.split(netloc)[1]
            elif entry["host"] and entry["host"] in http.uri:
                path = http.uri.split(entry["host"])[1]

            entry["data"] = convert_to_printable(tcpdata)
            entry["uri"] = convert_to_printable(urlunparse(("http", netloc, path, None, None, None)))
            entry["body"] = convert_to_printable(http.body)
            entry["path"] = convert_to_printable(path)
            entry["user-agent"] = convert_to_printable(http.headers["user-agent"]) if "user-agent" in http.headers else ""
            entry["version"] = convert_to_printable(http.version)
            entry["method"] = convert_to_printable(http.method)
            entry["first_seen"] = ts
            self.http_requests[tcpdata] = entry
        except Exception:
            return False

        return True

    def _https_identify(self, conn, data):
        """Extract a combination of the Session ID, Client Random, and Server
        Random in order to identify the accompanying master secret later."""
        try:
            record = dpkt.ssl.TLSRecord(data)
        except dpkt.NeedData:
            return
        except Exception:
            log.exception("Error reading possible TLS Record")
            return

        # Is this a valid TLS packet?
        if record.type not in dpkt.ssl.RECORD_TYPES:
            return

        try:
            record = dpkt.ssl.RECORD_TYPES[record.type](record.data)
        except (dpkt.NeedData, dpkt.ssl.SSL3Exception):
            return

        # Is this a TLSv1 Handshake packet?
        if not isinstance(record, dpkt.ssl.TLSHandshake):
            return

        # We're only interested in the TLS Server Hello packets.
        if not isinstance(record.data, dpkt.ssl.TLSServerHello):
            return

        # Extract the server random and the session id.
        self.tls_keys.append(
            {
                "server_random": binascii.b2a_hex(record.data.random),
                "session_id": binascii.b2a_hex(record.data.session_id),
            }
        )

    def _reassemble_smtp(self, conn, data):
        """Reassemble a SMTP flow.
        @param conn: connection dict.
        @param data: raw data.
        """
        self.smtp_flow.setdefault(conn["dst"], []).append(data)

    def _process_smtp(self):
        """Process SMTP flow."""
        # data is list
        for conn, data in self.smtp_flow.items():
            # Detect new SMTP flow.
            if b"EHLO" in data or b"HELO" in data:
                self.smtp_requests.append({"dst": conn, "raw": convert_to_printable(data)})

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

        if enabled_passlist and conn["src"] in ip_passlist or conn["dst"] in ip_passlist:
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
            self.irc_requests += client + server
        except Exception:
            return False

        return True

    def run(self):
        """Process PCAP.
        @return: dict with network analysis data.
        """
        log = logging.getLogger("Processing.Pcap")

        if not IS_DPKT:
            log.error("Python DPKT is not installed, aborting PCAP analysis")
            return self.results

        if not path_exists(self.filepath):
            log.debug(
                'The PCAP file does not exist at path "%s". Did you run analysis with live connection? Did you enable pcap in cuscom/conf/routing.conf?',
                self.filepath,
            )
            return self.results

        if os.path.getsize(self.filepath) == 0:
            log.error('The PCAP file at path "%s" is empty', self.filepath)
            return self.results

        try:
            file = open(self.filepath, "rb")
        except (IOError, OSError):
            log.error("Unable to open %s", self.filepath)
            return self.results

        try:
            pcap = dpkt.pcap.Reader(file)
        except dpkt.dpkt.NeedData:
            log.error('Unable to read PCAP file at path "%s"', self.filepath)
            return self.results
        except ValueError:
            log.error('Unable to read PCAP file at path "%s". File is corrupted or wrong format', self.filepath)
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
                    connection["src"] = socket.inet_ntop(socket.AF_INET6, ip.src)
                    connection["dst"] = socket.inet_ntop(socket.AF_INET6, ip.dst)
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

                    if tcp.data:
                        self._tcp_dissect(connection, tcp.data, ts)
                        src, sport, dst, dport = connection["src"], connection["sport"], connection["dst"], connection["dport"]
                        if not (
                            (dst, dport, src, sport) in self.tcp_connections_seen
                            or (src, sport, dst, dport) in self.tcp_connections_seen
                        ):
                            self.tcp_connections.append((src, sport, dst, dport, offset, ts - first_ts))
                            self.tcp_connections_seen.add((src, sport, dst, dport))
                        self.alive_hosts[dst, dport] = True
                    else:
                        ipconn = (
                            connection["src"],
                            tcp.sport,
                            connection["dst"],
                            tcp.dport,
                        )
                        seqack = self.tcp_connections_dead.get(ipconn)
                        if seqack == (tcp.seq, tcp.ack):
                            host = connection["dst"], tcp.dport
                            self.dead_hosts[host] = self.dead_hosts.get(host, 1) + 1

                        self.tcp_connections_dead[ipconn] = tcp.seq, tcp.ack

                elif ip.p == dpkt.ip.IP_PROTO_UDP:
                    udp = ip.data
                    if not isinstance(udp, dpkt.udp.UDP):
                        udp = dpkt.udp.UDP(udp)

                    connection["sport"] = udp.sport
                    connection["dport"] = udp.dport
                    if len(udp.data) > 0:
                        self._udp_dissect(connection, udp.data, ts)

                    src, sport, dst, dport = connection["src"], connection["sport"], connection["dst"], connection["dport"]
                    if not (
                        (dst, dport, src, sport) in self.udp_connections_seen
                        or (src, sport, dst, dport) in self.udp_connections_seen
                    ):
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

        # Build results dict.
        if not self.options.get("sorted", False):
            self.results["hosts"] = self._enrich_hosts(self.unique_hosts)
            self.results["domains"] = self.unique_domains
            self.results["tcp"] = [conn_from_flowtuple(i) for i in self.tcp_connections]
            self.results["udp"] = [conn_from_flowtuple(i) for i in self.udp_connections]
            self.results["icmp"] = self.icmp_requests
            self.results["http"] = list(self.http_requests.values())
            self.results["dns"] = list(self.dns_requests.values())
            self.results["smtp"] = self.smtp_requests
            self.results["irc"] = self.irc_requests
            self.results["dead_hosts"] = []
        else:
            self.results["sorted"] = {}
            self.results["sorted"]["tcp"] = [conn_from_flowtuple(i) for i in self.tcp_connections]
            self.results["sorted"]["udp"] = [conn_from_flowtuple(i) for i in self.udp_connections]

            if enabled_passlist:
                for keyword in ("tcp", "udp"):
                    for host in self.results["sorted"][keyword]:
                        for delip in ip_passlist:
                            if delip in (host["src"], host["dst"]):
                                self.results["sorted"][keyword].remove(host)
            return self.results

        # Report each IP/port combination as a dead host if we've had to retry
        # at least 3 times to connect to it and if no successful connections
        # were detected throughout the analysis.
        for (ip, port), count in self.dead_hosts.items():
            if count < 3 or (ip, port) in self.alive_hosts:
                continue

            # Report once.
            if (ip, port) not in self.results["dead_hosts"]:
                self.results["dead_hosts"].append((ip, port))

        # Remove hosts that have an IP which correlate to a passlisted domain
        if enabled_passlist:
            for host in self.results["hosts"]:
                for delip in ip_passlist:
                    if delip == host["ip"]:
                        self.results["hosts"].remove(host)

            for keyword in ("tcp", "udp", "icmp"):
                for host in self.results[keyword]:
                    for delip in ip_passlist:
                        if delip in (host["src"], host["dst"]):
                            self.results[keyword].remove(host)

        return self.results


class Pcap2:
    """Interpret the PCAP file through the httpreplay library which parses
    the various protocols, decrypts and decodes them, and then provides us
    with the high level representation of it."""

    def __init__(self, pcap_path, tlsmaster, network_path):
        self.pcap_path = pcap_path
        self.network_path = network_path

        self.handlers = {
            25: httpreplay.cut.smtp_handler,
            80: httpreplay.cut.http_handler,
            443: lambda: httpreplay.cut.https_handler(tlsmaster),
            465: httpreplay.cut.smtp_handler,
            587: httpreplay.cut.smtp_handler,
            4443: lambda: httpreplay.cut.https_handler(tlsmaster),
            8000: httpreplay.cut.http_handler,
            8080: httpreplay.cut.http_handler,
            8443: lambda: httpreplay.cut.https_handler(tlsmaster),
        }

    def run(self):
        results = {"http_ex": [], "https_ex": [], "smtp_ex": []}

        if not path_exists(self.network_path):
            path_mkdir(self.network_path, exist_ok=True)

        if not path_exists(self.pcap_path):
            log.warning('The PCAP file does not exist at path "%s"', self.pcap_path)
            return {}

        r = httpreplay.reader.PcapReader(open(self.pcap_path, "rb"))
        r.tcp = httpreplay.smegma.TCPPacketStreamer(r, self.handlers)

        try:
            sorted_r = sorted(r.process(), key=lambda x: x[1])
        except TypeError as e:
            log.warning("You running old httpreplay %s: poetry run pip install -U git+https://github.com/CAPESandbox/httpreplay", e)
            traceback.print_exc()
            return results
        except Exception as e:
            log.error("httpreplay error: %s", e)
            traceback.print_exc()
            return results

        for s, ts, protocol, sent, recv in sorted_r:
            srcip, srcport, dstip, dstport = s

            if enabled_passlist:
                """
                if is_safelisted_ip(dstip):
                    continue
                """
                # ToDo rewrite the whole safelists
                # ip or host

                if dstip in ip_passlist:
                    continue

                hostname = False
                if protocol == "smtp":
                    hostname = sent.hostname
                elif protocol in ("http", "https"):
                    hostname = sent.headers.get("host")

                for reject in domain_passlist_re:
                    if hostname and re.search(reject, hostname):
                        return False

            if protocol == "smtp":
                results["smtp_ex"].append(
                    {
                        "src": srcip,
                        "dst": dstip,
                        "sport": srcport,
                        "dport": dstport,
                        "protocol": protocol,
                        "req": {
                            "hostname": sent.hostname,
                            "mail_from": sent.mail_from,
                            "mail_to": sent.mail_to,
                            "auth_type": sent.auth_type,
                            "username": sent.username,
                            "password": sent.password,
                            "headers": sent.headers,
                            "mail_body": sent.message,
                        },
                        "resp": {"banner": recv.ready_message},
                        "first_seen": ts,
                    }
                )

            elif protocol in ("http", "https"):
                response = b""
                request = b""
                if isinstance(sent.raw, bytes):
                    request = sent.raw.split(b"\r\n\r\n", 1)[0]
                if isinstance(recv.raw, bytes):
                    response = recv.raw.split(b"\r\n\r\n", 1)[0]

                status = int(getattr(recv, "status", 0))
                tmp_dict = {
                    "src": srcip,
                    "sport": srcport,
                    "dst": dstip,
                    "dport": dstport,
                    "protocol": protocol,
                    "method": sent.method,
                    "host": sent.headers.get("host", dstip),
                    "uri": sent.uri,
                    "status": status,
                    # We'll keep these fields here for now.
                    "request": request,  # .decode("latin-1"),
                    "response": response,  # .decode("latin-1"),
                    "first_seen": ts,
                }

                if status and status not in (301, 302):
                    if sent.body:
                        req_md5 = md5(sent.body).hexdigest()
                        req_sha1 = sha1(sent.body).hexdigest()
                        req_sha256 = sha256(sent.body).hexdigest()

                        req_path = os.path.join(self.network_path, req_sha1)
                        _ = path_write_file(req_path, sent.body)

                        # It's not perfect yet, but it'll have to do.
                        tmp_dict["req"] = {
                            "path": req_path,
                            "md5": req_md5,
                            "sha1": req_sha1,
                            "sha256": req_sha256,
                        }

                    if recv.body:
                        resp_md5 = md5(recv.body).hexdigest()
                        resp_sha1 = sha1(recv.body).hexdigest()
                        resp_sha256 = sha256(recv.body).hexdigest()
                        resp_path = os.path.join(self.network_path, resp_sha256)
                        _ = path_write_file(resp_path, recv.body)
                        resp_preview = []
                        try:
                            c = 0
                            for i in range(3):
                                data = recv.body[c : c + 16]
                                if not data:
                                    continue
                                s1 = " ".join([f"{i:02x}" for i in data])  # hex string
                                s1 = f"{s1[:23]} {s1[23:]}"  # insert extra space between groups of 8 hex values
                                s2 = "".join([chr(i) if 32 <= i <= 127 else "." for i in data])  # ascii string; chained comparison
                                resp_preview.append(f"{i*16:08x}  {s1:<48}  |{s2}|")
                                c += 16
                        except Exception as e:
                            log.info(e)

                        tmp_dict["resp"] = {
                            "md5": resp_md5,
                            "sha1": resp_sha1,
                            "sha256": resp_sha256,
                            "preview": resp_preview,
                            "path": resp_path,
                        }

                results[f"{protocol}_ex"].append(tmp_dict)

        return results


class NetworkAnalysis(Processing):
    """Network analysis."""

    # ToDo map this to suricata.tls.ja
    def _import_ja3_fprints(self):
        """
        open and read ja3 fingerprint json file from:
        https://github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json
        :return: dictionary of ja3 fingerprint descreptions
        """
        ja3_fprints = {}
        if path_exists(self.ja3_file):
            with open(self.ja3_file, "r") as fpfile:
                for line in fpfile:
                    try:
                        ja3 = loads(line)
                        if "ja3_hash" in ja3 and "desc" in ja3:
                            ja3_fprints[ja3["ja3_hash"]] = ja3["desc"]
                    except Exception as e:
                        print(e)

        return ja3_fprints

    def run(self):
        self.key = "network"
        self.ja3_file = self.options.get("ja3_file", os.path.join(CUCKOO_ROOT, "data", "ja3", "ja3fingerprint.json"))
        if not IS_DPKT:
            log.error("Python DPKT is not installed, aborting PCAP analysis")
            return {}

        if not path_exists(self.pcap_path):
            log.warning('The PCAP file does not exist at path "%s"', self.pcap_path)
            return {}

        if os.path.getsize(self.pcap_path) == 0:
            log.error('The PCAP file at path "%s" is empty', self.pcap_path)
            return {}

        ja3_fprints = self._import_ja3_fprints()

        results = {"pcap_sha256": File(self.pcap_path).get_sha256()}
        self.options["sorted"] = False
        results.update(Pcap(self.pcap_path, ja3_fprints, self.options).run())

        if proc_cfg.network.sort_pcap:
            sorted_path = self.pcap_path.replace("dump.", "dump_sorted.")
            sort_pcap(self.pcap_path, sorted_path)
            if path_exists(sorted_path):
                results["sorted_pcap_sha256"] = File(sorted_path).get_sha256()
                self.options["sorted"] = True
                results.update(Pcap(sorted_path, ja3_fprints, self.options).run())

        if HAVE_HTTPREPLAY:
            try:
                p2 = Pcap2(self.pcap_path, self.get_tlsmaster(), self.network_path).run()
                if p2:
                    results.update(p2)
            except Exception:
                log.exception("Error running httpreplay-based PCAP analysis")

        return results

    def get_tlsmaster(self):
        """Obtain the client/server random to TLS master secrets mapping that we have obtained through dynamic analysis."""
        tlsmaster = {}
        dump_tls_log = os.path.join(self.analysis_path, "tlsdump", "tlsdump.log")
        if not path_exists(dump_tls_log):
            return tlsmaster

        for entry in open(dump_tls_log, "r").readlines() or []:
            try:
                for m in re.finditer(
                    r"client_random:\s*(?P<client_random>[a-f0-9]+)\s*,\s*server_random:\s*(?P<server_random>[a-f0-9]+)\s*,\s*master_secret:\s*(?P<master_secret>[a-f0-9]+)\s*",
                    entry,
                    re.I,
                ):
                    try:
                        client_random = binascii.a2b_hex(m.group("client_random").strip())
                        server_random = binascii.a2b_hex(m.group("server_random").strip())
                        master_secret = binascii.a2b_hex(m.group("master_secret").strip())
                        tlsmaster[client_random, server_random] = master_secret
                    except Exception as e:
                        log.warning("Problem dealing with tlsdump error: %s line: %s", e, m.group(0))
            except Exception as e:
                log.warning("Problem dealing with tlsdump error: %s line: %s", e, entry)

        return tlsmaster


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
    return {"src": sip, "sport": sport, "dst": dip, "dport": dport, "offset": offset, "time": relts}


# input_iterator should be a class that also supports writing so we can use it for the temp files
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
            with suppress(Exception):
                chunk.close()
                path_delete(chunk.name)


# magic
class SortCap:
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
        sip, dip, proto = "0", "0", -1
        sport, dport = 0, 0

    flowtuple = (sip, dip, sport, dport, proto)
    return flowtuple


def payload_from_raw(raw, linktype=1):
    """Get the payload from a packet, the data below TCP/UDP basically"""
    ip = iplayer_from_raw(raw, linktype)
    try:
        return ip.data.data
    except Exception:
        return b""


def next_connection_packets(piter, linktype=1):
    """Extract all packets belonging to the same flow from a pcap packet iterator"""
    first_ft = None

    for _, raw in piter:
        ft = flowtuple_from_raw(raw, linktype)
        if not first_ft:
            first_ft = ft

        sip, dip, sport, dport, proto = ft
        if first_ft not in (ft, (dip, sip, dport, sport, proto)):
            break

        yield {
            "src": sip,
            "dst": dip,
            "sport": sport,
            "dport": dport,
            "raw": b64encode(payload_from_raw(raw, linktype)).decode(),
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
