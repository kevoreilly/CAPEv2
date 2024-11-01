# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from contextlib import suppress

from modules.processing.parsers.CAPE.Zloader import extract_config

HAVE_MACO = False
with suppress(ImportError):
    from modules.processing.parsers.MACO.AgentTesla import convert_to_MACO

    HAVE_MACO = True


def test_zloader():
    with open("tests/data/malware/adbd0c7096a7373be82dd03df1aae61cb39e0a155c00bbb9c67abc01d48718aa", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "Botnet name": "Bing_Mod5",
            "Campaign ID": "M1",
            "address": ["https://dem.businessdeep.com"],
            "Public key": "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKGAOWVkikqE7TyKIMtWI8dFsaleTaJNXMJNIPnRE/fGCzqrV+rtY3+ex4MCHEtq2Vwppthf0Rglv8OiWgKlerIN5P6NEyCfIsFYUMDfldQTF03VES8GBIvHq5SjlIz7lawuwfdjdEkaHfOmmu9srraftkI9gZO8WRQgY1uNdsXwIDAQAB-----END PUBLIC KEY-----",
        }
        if HAVE_MACO:
            assert convert_to_MACO(conf).model_dump(exclude_defaults=True, exclude_none=True) == {
                "family": "Zloader",
                "campaign_id": ["M1"],
                "other": {
                    "Botnet name": "Bing_Mod5",
                    "Campaign ID": "M1",
                    "address": ["https://dem.businessdeep.com"],
                    "Public key": "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKGAOWVkikqE7TyKIMtWI8dFsaleTaJNXMJNIPnRE/fGCzqrV+rtY3+ex4MCHEtq2Vwppthf0Rglv8OiWgKlerIN5P6NEyCfIsFYUMDfldQTF03VES8GBIvHq5SjlIz7lawuwfdjdEkaHfOmmu9srraftkI9gZO8WRQgY1uNdsXwIDAQAB-----END PUBLIC KEY-----",
                },
                "http": [{"uri": "https://dem.businessdeep.com"}],
            }
