# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.integrations.mitre import load_mitre
from modules.reporting.mitre import generate_mitre_attck
from utils.community import install


def test_mitre_attck():

    mitre, HAVE_MITRE, pyattck_version = load_mitre(True)

    data = {"ttps" : [
        { "ttp": 'T1486', "signature": 'cape_detected_threat' },
        { "ttp": 'T1486', "signature": 'cape_extracted_content' },
    ]}

    # Download jsons here
    install(["mitre"], True, True)
    # test if version != 7, create list of tested versions
    if mitre:
        attck = generate_mitre_attck(data, mitre)
        assert "Impact" in attck
        assert len(attck["Impact"]) == 1
        assert sorted(attck["Impact"][0]["signature"]) == ['cape_detected_threat', 'cape_extracted_content']
