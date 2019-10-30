# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ClickfraudVolume(Signature):
    name = "clickfraud_volume"
    description = "Attempts to disable browser navigation sounds, indicative of click fraud"
    severity = 3
    categories = ["clickfraud"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["CoInternetSetFeatureEnabled"])

    def on_call(self, call, process):
        entry = int(self.get_argument(call, "FeatureEntry"), 10)
        buf = self.get_argument(call, "Enabled")
        if buf:
            enable = int(buf, 10)
        else:
            enable = None

        # FEATURE_DISABLE_NAVIGATION_SOUNDS
        if entry == 21 and enable:
            return True
