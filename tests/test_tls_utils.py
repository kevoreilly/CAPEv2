# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import unittest.mock as mock

from utils.tls import TLS12KeyLog, tlslog_to_sslkeylogfile

TLSDUMP_LOGS = [
    "client_random: 66d85f5e14959be90acdf46867ac60b1380a7c0fd4b0e8f18f66438d7840f0bb, server_random: 66d85f6626997dd836d354b522bab8426a6b9ee3daac68467d9d8f1fcdea07c0, master_secret: 70384eb96e90d023e3cc117d9f0f5b703b5cbb88897783e08286656aa40444ab1433c850bf556737d2c09b2d4c67094d"
]
SSLKEYLOGS = [
    "CLIENT_RANDOM 66d85f5e14959be90acdf46867ac60b1380a7c0fd4b0e8f18f66438d7840f0bb 70384eb96e90d023e3cc117d9f0f5b703b5cbb88897783e08286656aa40444ab1433c850bf556737d2c09b2d4c67094d"
]


class TestTlsUtils:
    def test_tlslog_to_sslkeylogfile(self, tmpdir):
        input_log = f"{tmpdir}/tlsdump.log"
        dest_log = f"{tmpdir}/sslkeys.log"
        with open(input_log, "w+") as tlsdump_log:
            tlsdump_log.writelines(TLSDUMP_LOGS)
        tlslog_to_sslkeylogfile(input_log, dest_log)
        with open(dest_log, "r") as sslkeylogfile:
            actual = sslkeylogfile.read().strip()
        assert actual == SSLKEYLOGS[0]

    @mock.patch("builtins.open")
    def test_tlslog_to_sslkeylogfile_path_not_exist(self, mock_open, tmpdir):
        mock_open.side_effect = mock.mock_open
        input_log = f"{tmpdir}/tlsdump.log"
        dest_log = f"{tmpdir}/sslkeys.log"
        tlslog_to_sslkeylogfile(input_log, dest_log)
        mock_open.assert_not_called()

    def test_tls12keylog_from_cape_log(self):
        actual = TLS12KeyLog.from_cape_log(TLSDUMP_LOGS[0])
        assert actual.client_random == "66d85f5e14959be90acdf46867ac60b1380a7c0fd4b0e8f18f66438d7840f0bb"
        assert actual.server_random == "66d85f6626997dd836d354b522bab8426a6b9ee3daac68467d9d8f1fcdea07c0"
        assert (
            actual.master_secret
            == "70384eb96e90d023e3cc117d9f0f5b703b5cbb88897783e08286656aa40444ab1433c850bf556737d2c09b2d4c67094d"
        )
        assert str(actual) == SSLKEYLOGS[0]
