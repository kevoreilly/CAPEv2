# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import HAVE_MITRE, mitre
from modules.reporting.mitre import generate_mitre_attck

def test_mitre_attck():
    data = {"ttps" : [
        { "ttp": 'T1486', "signature": 'cape_detected_threat' },
        { "ttp": 'T1486', "signature": 'cape_extracted_content' },
    ]}

    if HAVE_MITRE and mitre:
        attck = generate_mitre_attck(data, mitre)
        assert len(attck["Impact"]) == 1
        assert attck["Impact"][0]["signature"] == ['cape_detected_threat', 'cape_extracted_content']
