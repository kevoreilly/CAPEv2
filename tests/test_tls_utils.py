# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import unittest.mock as mock

from utils.tls import TLS12KeyLog, parse_tlsdump_line, tlslog_to_sslkeylogfile

TLSDUMP_LOGS = [
    "client_random: 66d85f5e14959be90acdf46867ac60b1380a7c0fd4b0e8f18f66438d7840f0bb, server_random: 66d85f6626997dd836d354b522bab8426a6b9ee3daac68467d9d8f1fcdea07c0, master_secret: 70384eb96e90d023e3cc117d9f0f5b703b5cbb88897783e08286656aa40444ab1433c850bf556737d2c09b2d4c67094d"
]
SSLKEYLOGS = [
    "CLIENT_RANDOM 66d85f5e14959be90acdf46867ac60b1380a7c0fd4b0e8f18f66438d7840f0bb 70384eb96e90d023e3cc117d9f0f5b703b5cbb88897783e08286656aa40444ab1433c850bf556737d2c09b2d4c67094d"
]
TLS13_LINES = [
    f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {'aa' * 32} {'bb' * 32}",
    f"SERVER_HANDSHAKE_TRAFFIC_SECRET {'aa' * 32} {'cc' * 32}",
    f"CLIENT_TRAFFIC_SECRET_0 {'aa' * 32} {'dd' * 32}",
    f"SERVER_TRAFFIC_SECRET_0 {'aa' * 32} {'ee' * 32}",
    f"EXPORTER_SECRET {'aa' * 32} {'ff' * 32}",
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

    def test_tlslog_to_sslkeylogfile_preserves_tls13_secrets(self, tmpdir):
        input_log = f"{tmpdir}/tlsdump.log"
        dest_log = f"{tmpdir}/sslkeys.log"
        with open(input_log, "w+") as tlsdump_log:
            tlsdump_log.write(TLSDUMP_LOGS[0] + "\n")
            for line in TLS13_LINES:
                tlsdump_log.write(line + "\n")
            tlsdump_log.write(f"CLIENT_TRAFFIC_SECRET_0 {'aa' * 32} {'00' * 32}\n")
        tlslog_to_sslkeylogfile(input_log, dest_log)
        with open(dest_log, "r") as sslkeylogfile:
            actual = sslkeylogfile.read().splitlines()
        assert actual == SSLKEYLOGS + TLS13_LINES
        assert parse_tlsdump_line(f"CLIENT_RANDOM {'aa' * 32} {'00' * 48}") is None

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
