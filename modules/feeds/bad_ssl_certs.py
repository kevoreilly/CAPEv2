# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from lib.cuckoo.common.abstracts import Feed

class AbuseCH_SSL(Feed):
    # Results dict key value / exception handling / logging name
    name = "Bad_SSL_Certs"
    # Change the below line to enable this feed
    enabled = False

    def __init__(self):
        Feed.__init__(self)
        # Location of the feed to be fetched
        self.downloadurl = "https://sslbl.abuse.ch/downloads/ssl_extended.csv"
        # Used in creating the file path on disk
        self.feedname = "abuse_ch_ssl"
        # How much time must pass (in hours) before we update
        self.frequency = 6

    def modify(self):
        newdata = ""
        seen = set()
        data = self.downloaddata
        for line in data.splitlines():
            item = line.split(",")
            # Ignore comments
            if len(item) != 6:
                pass
            else:
                # Ignore header column and deduplicate data
                if "SSL" not in item[4] and item[4] not in seen:
                    newdata += ",".join(item[4:6]) + "\n"
                seen.add(item[4])
        # When we modify download data, we must save this to the self.data
        # variable instead of self.downloaddata.
        self.data = newdata
