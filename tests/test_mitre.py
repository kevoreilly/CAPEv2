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
            {"signature": "http_request", "ttps": ["T1071"]},
            {"signature": "modify_proxy", "ttps": ["T1112"]},
            {"signature": "recon_fingerprint", "ttps": ["T1012", "T1082"]},
        ]
    }

    # Download mitre jsons here
    install(["mitre"], True, True, clean=False, url="https://github.com/kevoreilly/community/archive/master.tar.gz")
    attck = mitre_generate_attck(data, mitre)
    assert "Discovery" in attck
    assert len(attck["Discovery"]) == 2
    assert sorted(attck["Discovery"][0]["signature"]) == ["recon_fingerprint"]
    assert not attck["Discovery"][0]["t_id"].startswith("attack-pattern")
    assert attck["Discovery"][0]["t_id"] == "T1082"


if __name__ == "__main__":
    test_mitre_attck()
