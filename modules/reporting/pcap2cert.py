import hashlib
import logging
import os
import socket
import struct
from base64 import b64encode
from io import BufferedReader
from typing import Dict

import dpkt
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT

try:
    import OpenSSL.crypto as c

    HAS_OPENSSL = True
except ImportError:
    print("MISSED pcap2cert dependencies")
    HAS_OPENSSL = False

log = logging.getLogger(__name__)


class PCAP2CERT(Report):
    """Extract certs and convert them to PEM"""

    order = 1

    def convert_cert(self, data: bytes) -> bytes:
        # change c.FILETYPE_ASN to convert to DER/ASN1
        cert = c.load_certificate(c.FILETYPE_ASN1, data)
        return c.dump_certificate(c.FILETYPE_PEM, cert)

    def extract_file(self, f: BufferedReader) -> Dict[str, bytes]:
        doneList = []
        tcp_piece = {}
        certificates = {}
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception as e:
            log.info("Error: %s", e)
            return

        count = 0
        try:
            for _, buf in pcap:
                count += 1
                try:
                    ethernet = dpkt.ethernet.Ethernet(buf)
                    if not hasattr(ethernet, "data"):
                        continue

                    upperdata = ethernet.data
                    # iteratively find IP layer, as some connections have pppoe and ppp layers
                    while not isinstance(upperdata, (dpkt.ip.IP, str)):
                        upperdata = upperdata.data
                    if isinstance(upperdata, str):
                        continue
                    # if upperdata.sport != 443: continue
                    ippack = upperdata
                    tcppack = ippack.data
                    ssldata = tcppack.data
                    # drop empty packets, including those with similar SEQ replies
                    if not ssldata:
                        continue
                    srcip = socket.inet_ntoa(ippack.src)
                    if srcip in doneList:
                        continue
                    if not hasattr(tcppack, "seq"):
                        continue
                    tuple4 = (srcip, socket.inet_ntoa(ippack.dst), tcppack.sport, tcppack.dport)
                    tcp_piece.setdefault(tuple4, {})[tcppack.seq] = ssldata
                except Exception as e:
                    log.error(e)
        except Exception as e:
            log.error(e)

        for t4, dic in tcp_piece.items():
            srcip = t4[0]
            sport = t4[2]
            if srcip in doneList:
                continue
            seq = min(dic.keys())
            sslcombined = dic[seq]
            piecelen = len(dic[seq])
            while seq + piecelen in dic:
                seq += piecelen
                sslcombined += dic[seq]
                piecelen = len(dic[seq])
            totallen = len(sslcombined)

            curpos = 0
            while curpos < totallen and totallen - curpos >= 12 and sslcombined[curpos] == "\x16":
                handshake_len = struct.unpack("!H", sslcombined[curpos + 3 : curpos + 5])[0]
                curpos += 5
                cur_handshakelen = 0
                while cur_handshakelen < handshake_len and curpos + 4 < totallen:
                    this_handshake_len = struct.unpack("!I", "\x00" + sslcombined[curpos + 1 : curpos + 4])[0]
                    if sslcombined[curpos] == "\x0b":
                        # certificate
                        certlen = struct.unpack("!I", "\x00" + sslcombined[curpos + 4 : curpos + 7])[0]
                        # certificate length exceeded packet's length, caused by packet data loss
                        if certlen > totallen:
                            break
                        curpos += 7
                        sub_cert_len = 0
                        sub_cert_count = 1
                        while sub_cert_len < certlen:
                            this_sub_len = struct.unpack("!I", "\x00" + sslcombined[curpos : curpos + 3])[0]
                            curpos += 3
                            this_sub_cert = sslcombined[curpos : curpos + this_sub_len]
                            sub_cert_len += this_sub_len + 3  # +3 includes certificate length: 3 bytes
                            curpos += this_sub_len
                            md5cert = hashlib.md5(this_sub_cert).hexdigest()
                            filename = f"{srcip.replace('.', '_')}_{sport}_{sub_cert_count}_{md5cert}"
                            certificates.setdefault(filename, b64encode(this_sub_cert))  # self.convert_cert(this_sub_cert))
                            sub_cert_count += 1
                    else:
                        # skip if not certificate
                        curpos += this_handshake_len + 4
                    cur_handshakelen += this_handshake_len + 4

                if cur_handshakelen >= handshake_len:
                    continue

        return certificates

    def run(self, results: dict):
        """Run analysis.
        @return: {host:cert}.
        """

        if not HAS_OPENSSL:
            log.error("MISSED pcap2cert dependencies")
            return

        analysis_id = results.get("info", {}).get("id", None)
        pcap_path = f"{CUCKOO_ROOT}/storage/analyses/{analysis_id}/dump.pcap"
        if os.path.exists(pcap_path):
            with open(pcap_path, "rb") as file_pcap:
                certificates = self.extract_file(file_pcap)
            if certificates:
                results["certs"] = certificates
