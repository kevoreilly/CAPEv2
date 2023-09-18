# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from modules.processing.parsers.CAPE.CobaltStrikeBeacon import extract_config


def test_csb():
    with open("tests/data/malware/2588fd3232138f587e294aea5cc9a0611d1e165b199743552c84bfddc1e4c063", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "BeaconType": ["HTTP"],
            "Port": 4848,
            "SleepTime": 60000,
            "MaxGetSize": 1048576,
            "Jitter": 0,
            "MaxDNS": "Not Found",
            "PublicKey": "30819f300d06092a864886f70d010101050003818d0030818902818100bebe41805d3c15a738caf3e308a992d4d507ce827996a8c9d783c766963e7e73083111729ae0abc1b49af0bcf803efdcaf83ac694fb53d043a88e9333f169e026a3c4e63cc6d4cd1aa5e199cb95eec500f948ac472c0ab2eda385d35fb8592d74b1154a1c671afb310eccb0b139ee1100907bfcdd8dfbf3385803a11bc252995020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "C2Server": "192.144.206.100,/load",
            "UserAgent": "Not Found",
            "HttpPostUri": "/submit.php",
            "Malleable_C2_Instructions": [],
            "HttpGet_Metadata": "Not Found",
            "HttpPost_Metadata": "Not Found",
            "SpawnTo": "d7a9ca15a07f82bfd3b63020da38aa16",
            "PipeName": "Not Found",
            "DNS_Idle": "Not Found",
            "DNS_Sleep": "Not Found",
            "SSH_Host": "Not Found",
            "SSH_Port": "Not Found",
            "SSH_Username": "Not Found",
            "SSH_Password_Plaintext": "Not Found",
            "SSH_Password_Pubkey": "Not Found",
            "HttpGet_Verb": "GET",
            "HttpPost_Verb": "POST",
            "HttpPostChunk": 0,
            "Spawnto_x86": "%windir%\\syswow64\\rundll32.exe",
            "Spawnto_x64": "%windir%\\sysnative\\rundll32.exe",
            "CryptoScheme": 0,
            "Proxy_Config": "Not Found",
            "Proxy_User": "Not Found",
            "Proxy_Password": "Not Found",
            "Proxy_Behavior": "Use IE settings",
            "Watermark": 391144938,
            "bStageCleanup": "False",
            "bCFGCaution": "False",
            "KillDate": 0,
            "bProcInject_StartRWX": "True",
            "bProcInject_UseRWX": "True",
            "bProcInject_MinAllocSize": 0,
            "ProcInject_PrependAppend_x86": "Empty",
            "ProcInject_PrependAppend_x64": "Empty",
            "ProcInject_Execute": ["CreateThread", "SetThreadContext", "CreateRemoteThread", "RtlCreateUserThread"],
            "ProcInject_AllocationMethod": "VirtualAllocEx",
            "bUsesCookies": "True",
            "HostHeader": "",
        }
