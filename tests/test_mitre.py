# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.integrations.mitre import mitre_generate_attck, mitre_load
from utils.community import install


def test_mitre_attck():
    mitre, _, pyattck_version = mitre_load(True)
    assert mitre

    data = {
        "ttps": [
            {"ttp": "T1486", "signature": "cape_detected_threat"},
            {"ttp": "T1486", "signature": "cape_extracted_content"},
        ]
    }

    # Download mitre jsons here
    install(["mitre"], True, True, url="https://github.com/kevoreilly/community/archive/master.tar.gz")
    attck = mitre_generate_attck(data, mitre)
    assert "Impact" in attck
    assert len(attck["Impact"]) == 1
    assert sorted(attck["Impact"][0]["signature"]) == ["cape_detected_threat", "cape_extracted_content"]
    assert not attck["Impact"][0]["t_id"].startswith("attack-pattern")
    assert attck["Impact"][0]["t_id"] == "T1486"


if __name__ == "__main__":
    test_mitre_attck()
