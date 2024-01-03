# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from modules.processing.parsers.CAPE.NanoCore import extract_config


def test_nanocore():
    with open("tests/data/malware/f1bd511b69f95c26f489157272884a12225c1cf7a453207bfc46ce48a91eae96", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "BuildTime": "2023-11-22 00:25:26.569697",
            "Version": "1.2.2.0",
            "Mutex": "dc5ce709-95b6-4a26-9175-16a1a8446828",
            "DefaultGroup": "6coinc",
            "PrimaryConnectionHost": "6coinc.zapto.org",
            "BackupConnectionHost": "127.0.0.1",
            "ConnectionPort": "6696",
            "RunOnStartup": "True",
            "RequestElevation": "False",
            "BypassUserAccountControl": "True",
            "ClearZoneIdentifier": "True",
            "ClearAccessControl": "False",
            "SetCriticalProcess": "False",
            "PreventSystemSleep": "True",
            "ActivateAwayMode": "False",
            "EnableDebugMode": "False",
            "RunDelay": "0",
            "ConnectDelay": "4000",
            "RestartDelay": "5000",
            "TimeoutInterval": "5000",
            "KeepAliveTimeout": "30000",
            "MutexTimeout": "5000",
            "LanTimeout": "2500",
            "WanTimeout": "8000",
            "BufferSize": "65535",
            "MaxPacketSize": "10485760",
            "GCThreshold": "10485760",
            "UseCustomDnsServer": "True",
            "PrimaryDnsServer": "8.8.8.8",
            "BackupDnsServer": "8.8.4.4",
            "cncs": ["6coinc.zapto.org:6696", "127.0.0.1:6696"],
        }
