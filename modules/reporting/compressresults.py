# Copyright (C) 2017 Marirs.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import simplejson as json
from bson import ObjectId
from bson.binary import Binary
import zlib
from lib.cuckoo.common.abstracts import Report
import logging

log = logging.getLogger(__name__)

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

class CompressResults(Report):
    """Compresses certain results in the json dict before
        saving into MongoDB. This helps with the restriction
        of MongoDB document size of 16MB.
    """
    order = 9998
    # the order will change here when the order of
    # elastic & mongo python files order changes

    def run(self, results):

        for keyword in ("CAPE", "procdump"):
            if keyword in results:
                cape_json = json.dumps(results[keyword]).encode('utf8')
                compressed_data = zlib.compress(cape_json)
                results[keyword] = Binary(compressed_data)

        # compress behaviour analysis (enhanced & summary)
        for keyword in ("enhanced"):
            if keyword in results["behavior"]:
                compressed_behavior_enhanced = zlib.compress(JSONEncoder().encode(results["behavior"][keyword]).encode('utf8'))
                results["behavior"][keyword] = Binary(compressed_behavior_enhanced)
