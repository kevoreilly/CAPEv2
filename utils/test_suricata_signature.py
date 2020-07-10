from __future__ import absolute_import
from __future__ import print_function
import os, sys

if sys.version_info[:2] < (3, 5):
    sys.exit("You are running an incompatible version of Python, please use >= 3.5")

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.core.plugins import get_suricata_family

print("Suricata detects as:", get_suricata_family(sys.argv[1]))
