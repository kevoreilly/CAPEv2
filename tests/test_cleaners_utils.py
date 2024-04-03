# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common import cleaners_utils


def test_free_space_monitor(mocker):
    # Will not enter main loop
    cleaners_utils.free_space_monitor(return_value=True)
