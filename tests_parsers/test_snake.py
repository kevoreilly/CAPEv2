# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from modules.processing.parsers.CAPE.Snake import extract_config


def test_snake():
    with open("tests/data/malware/7b81c12fb7db9f0c317f36022ecac9faa45f5efefe24085c339c43db8b963ae2", "rb") as data:
        conf = extract_config(data.read())
        assert conf == {
            "Type": "Telegram",
            "C2": "https://api.telegram.org/bot7952998151:AAFh98iY7kaOlHAR0qftD3ZcqGbQm0TXbBY/sendMessage?chat_id=5692813672",
        }
