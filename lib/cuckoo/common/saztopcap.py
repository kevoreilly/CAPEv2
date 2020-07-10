# Copyright (C) 2016 Will Metcalf
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import logging
import zipfile
import shutil
from xml.dom.minidom import parse, parseString

try:
    from scapy.utils import PcapWriter
    from scapy.all import *

    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False
import glob
import os
import tempfile
import random
from lib.cuckoo.common.utils import store_temp_file
import random

try:
    import re2 as re
except ImportError:
    import re

log = logging.getLogger(__name__)


def build_handshake(src, dst, sport, dport, pktdump, smac, dmac):
    ipsrc = src
    ipdst = dst
    portsrc = sport
    portdst = dport
    client_isn = random.randint(1024, 10000)
    server_isn = random.randint(1024, 10000)
    syn = Ether(src=smac, dst=dmac) / IP(src=ipsrc, dst=ipdst) / TCP(flags="S", sport=portsrc, dport=portdst, seq=client_isn)
    synack = (
        Ether(src=dmac, dst=smac) / IP(src=ipdst, dst=ipsrc) / TCP(flags="SA", sport=portdst, dport=portsrc, seq=server_isn, ack=syn.seq + 1)
    )
    ack = (
        Ether(src=smac, dst=dmac) / IP(src=ipsrc, dst=ipdst) / TCP(flags="A", sport=portsrc, dport=portdst, seq=syn.seq + 1, ack=synack.seq + 1)
    )
    pktdump.write(syn)
    pktdump.write(synack)
    pktdump.write(ack)
    return (ack.seq, ack.ack)


def build_finshake(src, dst, sport, dport, seq, ack, pktdump, smac, dmac):
    ipsrc = src
    ipdst = dst
    portsrc = sport
    portdst = dport
    finAck = Ether(src=smac, dst=dmac) / IP(src=ipsrc, dst=ipdst) / TCP(flags="FA", sport=sport, dport=dport, seq=seq, ack=ack)
    finalAck = (
        Ether(src=dmac, dst=smac) / IP(src=ipdst, dst=ipsrc) / TCP(flags="A", sport=dport, dport=sport, seq=finAck.ack, ack=finAck.seq + 1)
    )
    pktdump.write(finAck)
    pktdump.write(finalAck)


def chunkstring(string, length):
    return (string[0 + i : length + i] for i in range(0, len(string), length))


def make_pkts(src, dst, sport, dport, seq, ack, payload, pktdump, smac, dmac):
    segments = []
    if len(payload) > 1460:
        segments = chunkstring(payload, 1460)
    else:
        segments.append(payload)
    ipsrc = src
    ipdst = dst
    portsrc = sport
    portdst = dport
    for segment in segments:
        p = Ether(src=smac, dst=dmac) / IP(src=ipsrc, dst=ipdst) / TCP(flags="PA", sport=sport, dport=dport, seq=seq, ack=ack) / segment
        returnAck = (
            Ether(src=dmac, dst=smac)
            / IP(src=ipdst, dst=ipsrc)
            / TCP(flags="A", sport=dport, dport=sport, seq=p.ack, ack=(p.seq + len(p[Raw])))
        )
        seq = returnAck.ack
        ack = returnAck.seq
        pktdump.write(p)
        pktdump.write(returnAck)
    return (returnAck.seq, returnAck.ack)


def saz_to_pcap(sazpath):
    if not sazpath.lower().endswith(".saz"):
        return None

    if not HAVE_SCAPY:
        log.error("Scapy is required for SAZ to PCAP conversion.")
        return None

    tmpdir = ""
    pcappath = "%s/%s.pcap" % (tempfile.mkdtemp(), os.path.basename(sazpath))
    fiddler_raw_dir = ""
    pktdump = PcapWriter(pcappath, sync=True)
    try:
        tmpdir = tempfile.mkdtemp()
    except Exception as e:
        log.error("Failed to Create temp dir for SAZ extraction %s" % (e))
        return None

    try:
        z = zipfile.ZipFile(sazpath, "r")
    except Exception as e:
        log.error("Failed to open SAZ file as Zip extraction %s" % (e))
        return None

    try:
        z.extractall(tmpdir)
        z.close()
    except Exception as e:
        log.error("Failed to extract SAZ file to temp dir %s" % (e))
        return None

    if not os.path.isdir("%s/raw/" % (tmpdir)):
        return None

    fiddler_raw_dir = "%s/raw/" % (tmpdir)
    m_file_list = glob.glob("%s/%s" % (fiddler_raw_dir, "*_m.xml"))
    m_file_list.sort()
    if m_file_list:
        for xml_file in m_file_list:
            sport = random.randint(1024, 65535)
            src = "192.168.1.1"
            smac = "00:11:22:aa:bb:cc"
            dport = 80
            dst = "10.1.1.1"
            dmac = "c0:c1:c0:b7:ce:63"
            dom = parse(xml_file)
            m = re.match(r"^(?P<fid>\d+)_m\.xml", os.path.basename(xml_file))
            if m:
                fid = m.group("fid")
            else:
                log.error("Failed to find fiddler ID tag")
                return None

            xmlTags = dom.getElementsByTagName("SessionFlag")
            for xmlTag in xmlTags:
                xmlTag = xmlTag.toxml()
                m = re.match(
                    r"\<SessionFlag N=\x22x-(?:client(?:ip\x22 V=\x22[^\x22]*?(?P<clientip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|port\x22 V=\x22(?P<sport>\d+))|hostip\x22 V=\x22[^\x22]*?(?P<hostip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\x22",
                    xmlTag,
                )
                # TODO:to enable this we need to track 5 tuples otherwise we have session reuse issues
                # if m and m.group("sport"):
                # sport = int(m.group("sport"))
                if m and m.group("clientip") and src == None:
                    src = m.group("clientip")
                elif m and m.group("hostip"):
                    dst = m.group("hostip")
            req = open(fiddler_raw_dir + fid + "_c.txt").read()
            m = re.match(r"^(?P<verb>[^\r\n\s]+)\s+(?P<host_and_port>https?\:\/\/[^\/\r\n\:]+(\:(?P<dport>\d{1,5}))?)\/", req)
            if m and m.group("verb") != "CONNECT":
                req = req.replace(m.group("host_and_port"), "", 1)
                if m.group("dport") and int(m.group("dport")) <= 65535:
                    dport = int(m.group("dport"))
            resp = open(fiddler_raw_dir + fid + "_s.txt").read()
            (seq, ack) = build_handshake(src, dst, sport, dport, pktdump, smac, dmac)
            (seq, ack) = make_pkts(src, dst, sport, dport, seq, ack, req, pktdump, smac, dmac)
            (seq, ack) = make_pkts(dst, src, dport, sport, seq, ack, resp, pktdump, dmac, smac)
            build_finshake(src, dst, sport, dport, seq, ack, pktdump, smac, dmac)
    else:
        m_file_list = glob.glob("%s/%s" % (fiddler_raw_dir, "*_c.txt"))
        m_file_list.sort()
        if m_file_list:
            for xml_file in m_file_list:
                sport = random.randint(1024, 65535)
                dport = 80
                src = "192.168.1.1"
                smac = "00:11:22:aa:bb:cc"
                dst = "10.1.1.1"
                dmac = "c0:c1:c0:b7:ce:63"
                m = re.match(r"^(?P<fid>\d+)_c\.txt", os.path.basename(xml_file))
                if m:
                    fid = m.group("fid")
                else:
                    log.error("Failed to find fiddler ID tag")
                    return None

                req = open(fiddler_raw_dir + fid + "_c.txt").read()
                m = re.match(r"^(?P<verb>[^\r\n\s]+)\s+(?P<host_and_port>https?\:\/\/[^\/\r\n\:]+(\:(?P<dport>\d{1,5}))?)\/", req)
                if m and m.group("verb") != "CONNECT":
                    req = req.replace(m.group("host_and_port"), "", 1)
                    if m.group("dport") and int(m.group("dport")) <= 65535:
                        dport = int(m.group("dport"))
                resp = open(fiddler_raw_dir + fid + "_s.txt").read()
                (seq, ack) = build_handshake(src, dst, sport, dport, pktdump, smac, dmac)
                (seq, ack) = make_pkts(src, dst, sport, dport, seq, ack, req, pktdump, smac, dmac)
                (seq, ack) = make_pkts(dst, src, dport, sport, seq, ack, resp, pktdump, dmac, smac)
                build_finshake(src, dst, sport, dport, seq, ack, pktdump, smac, dmac)
        else:
            log.error("Unsupported SAZ format")
            return None

    pktdump.close()
    if tmpdir:
        try:
            shutil.rmtree(tmpdir)
        except:
            pass
    return pcappath
