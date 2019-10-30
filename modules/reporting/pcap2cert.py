#coding=utf-8
from __future__ import absolute_import
from __future__ import print_function
import os
import dpkt
import struct
import socket
import hashlib
import logging
from base64 import b64encode
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
import six

try:
    import Crypto.Util.asn1 as asn1
    import OpenSSL.crypto as c
    HAS_OPENSSL = True
except ImportError:
    print("MISSED pcap2cert dependencies")
    HAS_OPENSSL = False

log = logging.getLogger(__name__)

class PCAP2CERT(Report):
    """Extract certs and convert them to PEM"""

    order = 1

    def convert_cert(self, data):
        # change c.FILETYPE_ASN to convert to DER/ASN1
        cert = c.load_certificate(c.FILETYPE_ASN1, data)
        dumped_cert = c.dump_certificate(c.FILETYPE_PEM, cert)
        return dumped_cert

    def extract_file(self, f):

        doneList = []
        tcp_piece = {}
        certificates = {}
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception as e:
            log.info("Error: {}".format(e))
            return

        count=0
        try:
            for ts, buf in pcap:
                count+=1
                try:
                    ethernet = dpkt.ethernet.Ethernet(buf)
                    if not hasattr(ethernet, "data"):
                        continue

                    upperdata=ethernet.data
                    while upperdata.__class__ not in [dpkt.ip.IP, str]:   #循环去找IP层，这主要是解决一些网络有pppoe和ppp层的缘故
                        upperdata=upperdata.data
                    if upperdata.__class__==dpkt.ip.IP:
                        #if upperdata.sport!=443: continue
                        ippack=upperdata
                        tcppack=ippack.data
                        ssldata=tcppack.data
                    else:   # IP层未找到
                        continue
                    if not ssldata:
                        continue    #如果是空就扔掉了，包括那个同一个SEQ对应的ACK的包
                    srcip=socket.inet_ntoa(ippack.src)
                    if srcip in doneList:
                        continue
                    #定义了一个四元组（源IP，目的IP，源端口，目的端口）
                    if not hasattr(tcppack, "seq"):
                        continue
                    tuple4=(srcip, socket.inet_ntoa(ippack.dst), tcppack.sport, tcppack.dport)
                    seq=tcppack.seq
                    if tuple4 not in tcp_piece:
                        tcp_piece[tuple4]={}
                    tcp_piece[tuple4][seq]=ssldata
                except Exception as e:
                    log.error(e)
        except Exception as e:
            log.error(e)

        #A->B和B->A是按两个流统计的，所以遍历一边源，就可以遍历到所有情况。
        for t4,dic in six.iteritems(tcp_piece):    #根据4元组进行组流
            srcip=t4[0]
            sport=t4[2]
            if srcip in doneList:
                continue
            seq=min(dic.keys())
            sslcombined=dic[seq]
            piecelen=len(dic[seq])
            while(seq + piecelen in dic):
                seq=seq + piecelen
                sslcombined += dic[seq]
                piecelen=len(dic[seq])
            totallen=len(sslcombined)

            #do something
            curpos=0
            while(curpos<totallen):
                #如果特别小，直接跳过
                if totallen-curpos<12: break
                #如果不是Handshake类型
                if sslcombined[curpos]!='\x16':
                    break
                handshake_len=struct.unpack('!H', sslcombined[curpos+3:curpos+5])[0]
                curpos+=5
                cur_handshakelen=0
                while(cur_handshakelen<handshake_len and curpos+4<totallen):
                    this_handshake_len=struct.unpack('!I', '\x00'+sslcombined[curpos+1:curpos+4])[0]
                    if sslcombined[curpos]=='\x0b': #如果这一段是证书
                        certlen=struct.unpack('!I', '\x00'+sslcombined[curpos+4:curpos+7])[0]
                        if certlen>totallen:    #证书的长度超过了数据包的长度，通常是数据包数据丢失导致的
                            break
                        curpos+=7
                        sub_cert_len=0  #所有子证书的总大小
                        sub_cert_count=1    #子证书编号，编号形成证书链，越靠下越小
                        while(sub_cert_len<certlen):
                            this_sub_len=struct.unpack('!I', '\x00'+sslcombined[curpos:curpos+3])[0]   #当前子证书大小
                            curpos+=3
                            this_sub_cert=sslcombined[curpos:curpos+this_sub_len]
                            sub_cert_len+=this_sub_len+3    #+3是“证书长度”，3个字节
                            curpos+=this_sub_len
                            md5cert=hashlib.md5(this_sub_cert).hexdigest()
                            filename='%s_%d_%d_%s' % (srcip.replace(".","_"), sport, sub_cert_count, md5cert)
                            certificates.setdefault(filename, b64encode(this_sub_cert))#self.convert_cert(this_sub_cert))
                            sub_cert_count+=1
                    else:
                        curpos+=this_handshake_len+4  #不是证书直接跳过
                    cur_handshakelen+=this_handshake_len+4

                if cur_handshakelen>=handshake_len:
                    continue

        return certificates

    def run(self, results):
        """Run analysis.
        @return: {host:cert}.
        """

        if not HAS_OPENSSL:
            log.error("MISSED pcap2cert dependencies")
            return

        id = results.get('info', {}).get('id', None)
        pcap_path = '{}/storage/analyses/{}/dump.pcap'.format(CUCKOO_ROOT, id)
        if os.path.exists(pcap_path):
            file_pcap = open(pcap_path, "rb")
            certificates = self.extract_file(file_pcap)
            file_pcap.close()
            if certificates:
                results["certs"] = certificates
