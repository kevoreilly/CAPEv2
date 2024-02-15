# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from modules.processing.parsers.CAPE.Njrat import extract_config


def test_njrat():
    with open("tests/data/malware/09bf19c00f3d8c63b8896edadd4622724a01f7d74de583733ee57a7d11eacd86", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "cncs": ["peter-bikini.gl.at.ply.gg:64215"],
            "campaign id": "HacKed",
            "version": "Njrat 0.7 Golden By Hassan Amiri",
        }


"""
https://github.com/kevoreilly/CAPEv2/pull/1957

09bf19c00f3d8c63b8896edadd4622724a01f7d74de583733ee57a7d11eacd86
2a5eb2f4bb25b89a9c3d325d893b87ed58fe87a6ada67c24f7cdef54b2138567
2e18a6a4b191741e57d8fb63bddb498f769344130e0f658d8ef5d74bd95c5c9b
4c8198288b00c70aeb7c9fcaae179873c618c1d5a804d36a54ac6e5c7fbacee2
4e1a8dff073c5648dbeaf55a6b3320461bcb0252cee9f8f5624f46e6d05b6584
55acd192c7cca3e46b8d1c0a24f98259ae093762722de3493a7da248e83ec07c
59f0979f3123e02ee0a13e3afa6b45d27b2fdbae75edc339d57d473d340851d8
5b147e624ad96d036c27aa9f526ed2e7daa9ca7bfe6639404dc8e71e1177a145
614b15eaa2b19e4f9ddb26639dbf5574126f552ae48afd7899a77bd6c7b8980d
646ed3f6856f58b90b4641ab24cdd1b6f9860b44243dfeaec952df7f0954b18a
710507e1f3e61b7010a445728b3c414efe068e22cac28c1dd3b8db56968262d7
77d1fcf6f8bea79cac80e284a9a5dbcc36b8b57eb86c9b74c538107d4baa2c1a
8b1b215f6a6f9881bc2b76ab409b0dff080dca31c538147a9d273ba7d05919e9
a4e7f6de5b6c1514b5a4e3361191624127320bcff249ad16207ce79644ffb9c1
a6c954599bf0b6a3f4e5b1d8bed604a09d1115a6b35b7e9a6de66f11a9977b81
aeece6134d1a1f0789c8c35d2541164ebc6f23511e2d6781497a82e1bec73abd
af2d5ae5ed7a72a3fa6a36cda93e163b84d8ad70a78afb08bcd1afa63d54f61e
bb7efdb9cb3673c1768a0681989e2662d3f9683b45aded8f5b780a3310bec1bb
c2c788ce1d3e55537c75684ceb961c01d9d9d0eb6b69c915c58433943320ffe5
e5967d1012f24bad8914ecfbc79af2211ef491a4a16e2ac390d7d26089c5307a
e69befafb01863bce3c730481fa21ff8e57c72351eec8002154538fe01e3cc9e
e8636547c991ba1557cf0532a143ad2316427e773bcbe474a60d8ba2bcf3cea3
f45abfb1e4d789528a7ce1469255a249a6cdf010045868992689d28c2b791719
"""
