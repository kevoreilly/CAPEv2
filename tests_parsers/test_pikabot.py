# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from contextlib import suppress

from modules.processing.parsers.CAPE.PikaBot import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.PikaBot import convert_to_MACO

    HAVE_MACO = True


def test_pikabot():
    with open("tests/data/malware/7600d0efc92ecef06320a1a6ffd85cd90d3d98470a381b03202e81d93bcdd03c", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "C2s": [
                "154.53.55.165:13783",
                "158.247.240.58:5632",
                "70.34.223.164:5000",
                "70.34.199.64:9785",
                "45.77.63.237:5632",
                "198.38.94.213:2224",
                "94.72.104.80:5000",
                "84.46.240.42:2083",
                "154.12.236.248:13786",
                "94.72.104.77:13724",
                "209.126.86.48:1194",
            ],
            "Version": "1.8.32-beta",
            "User Agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
            "Campaign Name": "GG24_T@T@f0adda360d2b4ccda11468e026526576",
            "Registry Key": "MWnkl",
        }
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "PikaBot",
                "version": "1.8.32-beta",
                "campaign_id": ["GG24_T@T@f0adda360d2b4ccda11468e026526576"],
                "other": {
                    "C2s": [
                        "154.53.55.165:13783",
                        "158.247.240.58:5632",
                        "70.34.223.164:5000",
                        "70.34.199.64:9785",
                        "45.77.63.237:5632",
                        "198.38.94.213:2224",
                        "94.72.104.80:5000",
                        "84.46.240.42:2083",
                        "154.12.236.248:13786",
                        "94.72.104.77:13724",
                        "209.126.86.48:1194",
                    ],
                    "Version": "1.8.32-beta",
                    "User Agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    "Campaign Name": "GG24_T@T@f0adda360d2b4ccda11468e026526576",
                    "Registry Key": "MWnkl",
                },
                "http": [
                    {
                        "hostname": "154.53.55.165",
                        "port": 13783,
                        "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    },
                    {
                        "hostname": "158.247.240.58",
                        "port": 5632,
                        "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    },
                    {
                        "hostname": "70.34.223.164",
                        "port": 5000,
                        "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    },
                    {
                        "hostname": "70.34.199.64",
                        "port": 9785,
                        "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    },
                    {
                        "hostname": "45.77.63.237",
                        "port": 5632,
                        "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    },
                    {
                        "hostname": "198.38.94.213",
                        "port": 2224,
                        "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    },
                    {
                        "hostname": "94.72.104.80",
                        "port": 5000,
                        "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    },
                    {
                        "hostname": "84.46.240.42",
                        "port": 2083,
                        "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    },
                    {
                        "hostname": "154.12.236.248",
                        "port": 13786,
                        "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    },
                    {
                        "hostname": "94.72.104.77",
                        "port": 13724,
                        "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    },
                    {
                        "hostname": "209.126.86.48",
                        "port": 1194,
                        "user_agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; A7F; BRI/2; Tablet PC 2.0; wbx 1.0.0; Microsoft Outlook 14.0.7233; ms-office;",
                    },
                ],
                "registry": [{"key": "MWnkl"}],
            }
