from __future__ import absolute_import
from __future__ import print_function
import os, sys

if sys.version_info[:2] < (3, 5):
    sys.exit("You are running an incompatible version of Python, please use >= 3.5")

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.core.plugins import get_suricata_family

#ET MALWARE Sharik/Smoke CnC Beacon 11
#ETPRO TROJAN MSIL/Revenge-RAT CnC Checkin
#ETPRO TROJAN Win32/Predator The Thief Initial CnC Checkin

assert "Smoke" == get_suricata_family("ET MALWARE Sharik/Smoke CnC Beacon 11")
assert "Revenge-Rat" == get_suricata_family("ETPRO TROJAN MSIL/Revenge-RAT CnC Checkin")
assert "Predator" == get_suricata_family("ETPRO TROJAN Win32/Predator The Thief Initial CnC Checkin")
assert "Medusahttp" == get_suricata_family("ET TROJAN MedusaHTTP Variant CnC Checkin M2")
assert False is get_suricata_family("ETPRO TROJAN Virus.Win32.Lamer.bd checkin")
assert False is get_suricata_family("ETPRO TROJAN Custom Cobalt Strike Beacon UA")
assert False is get_suricata_family("ET TROJAN Unit42 PoisonIvy Keepalive to CnC")
assert False is get_suricata_family("ET TROJAN Hacking Team Implant Exfiltration")
assert False is get_suricata_family("ET MALWARE User Agent (TEST) - Likely Webhancer Related Spyware")
assert False is get_suricata_family("ET MALWARE Media Pass ActiveX Install")
assert False is get_suricata_family("ETPRO TROJAN Google Docs Phishing Landing Dec 18 2016")
assert False is get_suricata_family("ETPRO TROJAN PowerShell Downloader CnC Checkin")
