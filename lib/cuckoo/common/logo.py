# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import sys
import random

from lib.cuckoo.common.colors import color, yellow
from lib.cuckoo.common.constants import CUCKOO_VERSION


def logo():
    """Cuckoo asciiarts.
    @return: asciiarts array.
    """
    logos = []

    logos.append(
        """
                               ),-.     /
  Cuckoo Sandbox              <(a  `---','
     no chance for malwares!  ( `-, ._> )
                               ) _>.___/
                                   _/"""
    )

    logos.append(
        """
  .-----------------.
  | Cuckoo Sandbox? |
  |     OH NOES!    |\\  '-.__.-'
  '-----------------' \\  /oo |--.--,--,--.
                         \\_.-'._i__i__i_.'
                               \"\"\"\"\"\"\"\"\""""
    )

    print((color(random.choice(logos), random.randrange(31, 37))))
    print()
    print((" Cuckoo Sandbox %s" % yellow(CUCKOO_VERSION)))
    print(" www.cuckoosandbox.org")
    print(" Copyright (c) 2010-2015")
    print()
    print(" CAPE: Config and Payload Extraction")
    print(" github.com/kevoreilly/CAPEv2")
    print()
    sys.stdout.flush()
