"""End-to-end tests for the tshark based Pcap2 parser.

The pcaps are built byte by byte so the expected payloads are known exactly, and tshark is
invoked for real: mocking its JSON output only proves that the mock matches the parser.
"""

import base64
import gzip
import os
import shutil
import ssl
import struct
import subprocess
import sys

import pytest

from lib.cuckoo.common import utils as cuckoo_utils
from modules.processing.network import Pcap2

pytestmark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark is not installed")


@pytest.fixture(autouse=True)
def _isolate_files_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(cuckoo_utils, "CUCKOO_ROOT", str(tmp_path))

CLIENT_IP = "192.168.1.10"
SERVER_IP = "104.244.42.1"
SMTP_SERVER_IP = "203.0.113.25"

RESPONSE_BODY = b"\x4d\x5a\x90\x00\x03\x00\x00\x00\xff\xfe\x00\x01binary-body"
POST_BODY = b"user=admin&pass=1234"
MAIL_BODY = b"stolen data line 1\r\nstolen data line 2\r\n"


def _ip(dotted):
    return bytes(int(octet) for octet in dotted.split("."))


def _frame(src, dst, sport, dport, seq, ack, payload):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, 0x18, 8192, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0x1234, 0x4000, 64, 6, 0, _ip(src), _ip(dst)) + tcp
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip


def _write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, data in enumerate(frames):
            f.write(struct.pack("<IIII", 1, index * 10000, len(data), len(data)))
            f.write(data)
    return path


@pytest.fixture
def http_pcap(tmp_path):
    """One answered GET, one unanswered POST with a body, one unanswered GET on a second stream."""
    request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(len(RESPONSE_BODY)).encode() + b"\r\n\r\n" + RESPONSE_BODY
    )
    post = (
        b"POST /submit HTTP/1.1\r\nHost: example.com\r\n"
        b"Content-Length: " + str(len(POST_BODY)).encode() + b"\r\n\r\n" + POST_BODY
    )
    orphan = b"GET /orphan HTTP/1.1\r\nHost: orphan.example\r\n\r\n"

    frames = [
        _frame(CLIENT_IP, SERVER_IP, 12345, 80, 1, 1, request),
        _frame(SERVER_IP, CLIENT_IP, 80, 12345, 1, 1 + len(request), response),
        _frame(CLIENT_IP, SERVER_IP, 12345, 80, 1 + len(request), 1 + len(response), post),
        _frame(CLIENT_IP, SERVER_IP, 12346, 80, 1, 1, orphan),
    ]
    return _write_pcap(str(tmp_path / "http.pcap"), frames)


@pytest.fixture
def smtp_pcap(tmp_path):
    """A full SMTP session: EHLO, AUTH LOGIN, MAIL/RCPT, DATA and the message."""
    mail = b"From: attacker@evil.test\r\nTo: victim@corp.test\r\nSubject: exfil\r\n\r\n" + MAIL_BODY + b".\r\n"
    conversation = [
        (False, b"220 mail.evil.test ESMTP Postfix\r\n"),
        (True, b"EHLO workstation\r\n"),
        (False, b"250-mail.evil.test\r\n250 AUTH LOGIN\r\n"),
        (True, b"AUTH LOGIN\r\n"),
        (False, b"334 VXNlcm5hbWU6\r\n"),
        (True, base64.b64encode(b"attacker@evil.test") + b"\r\n"),
        (False, b"334 UGFzc3dvcmQ6\r\n"),
        (True, base64.b64encode(b"SuperSecret123") + b"\r\n"),
        (False, b"235 2.7.0 Authentication successful\r\n"),
        (True, b"MAIL FROM:<attacker@evil.test>\r\n"),
        (False, b"250 2.1.0 Ok\r\n"),
        (True, b"RCPT TO:<victim@corp.test>\r\n"),
        (False, b"250 2.1.5 Ok\r\n"),
        (True, b"DATA\r\n"),
        (False, b"354 End data with <CR><LF>.<CR><LF>\r\n"),
        (True, mail),
        (False, b"250 2.0.0 Ok: queued\r\n"),
        (True, b"QUIT\r\n"),
    ]

    frames = []
    client_seq = server_seq = 1
    for from_client, payload in conversation:
        if from_client:
            frames.append(_frame(CLIENT_IP, SMTP_SERVER_IP, 52000, 25, client_seq, server_seq, payload))
            client_seq += len(payload)
        else:
            frames.append(_frame(SMTP_SERVER_IP, CLIENT_IP, 25, 52000, server_seq, client_seq, payload))
            server_seq += len(payload)
    return _write_pcap(str(tmp_path / "smtp.pcap"), frames)


class TestPcap2Tshark:
    def test_tshark_field_set_is_valid(self, http_pcap, tmp_path):
        """tshark aborts before emitting a packet if any requested field does not exist."""
        pcap2 = Pcap2(http_pcap, {}, str(tmp_path / "network"))
        packets = list(pcap2._iter_packets("http", Pcap2.METADATA_FIELDS, None))
        assert packets, "no packets parsed: tshark most likely rejected one of METADATA_FIELDS"

    def test_http_request_and_response(self, http_pcap, tmp_path):
        network_path = tmp_path / "network"
        results = Pcap2(http_pcap, {}, str(network_path)).run()

        flows = {(flow["method"], flow["uri"]): flow for flow in results["http_ex"]}
        # the answered GET, the unanswered POST and the unanswered GET on the second stream
        assert set(flows) == {("GET", "/index.html"), ("POST", "/submit"), ("GET", "/orphan")}

        get = flows[("GET", "/index.html")]
        assert get["src"] == CLIENT_IP
        assert get["sport"] == 12345
        assert get["dst"] == SERVER_IP
        assert get["dport"] == 80
        assert get["host"] == "example.com"
        assert get["status"] == 200
        assert get["protocol"] == "http"
        # the request/status line must be present, http.request.line only holds the headers
        assert get["request"] == b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n"
        assert get["response"].startswith(b"HTTP/1.1 200 OK\r\n")

    def test_http_body_is_extracted_verbatim(self, http_pcap, tmp_path):
        """http.file_data is hex encoded; storing it without decoding corrupts every body."""
        network_path = tmp_path / "network"
        results = Pcap2(http_pcap, {}, str(network_path)).run()

        get = next(flow for flow in results["http_ex"] if flow["uri"] == "/index.html")
        dumped = network_path / get["resp"]["sha256"]
        assert dumped.is_symlink()
        assert os.readlink(dumped) == cuckoo_utils.get_files_storage_path(get["resp"]["sha256"])
        assert dumped.read_bytes() == RESPONSE_BODY
        assert get["resp"]["preview"][0].endswith("|MZ..........bina|")

        post = next(flow for flow in results["http_ex"] if flow["uri"] == "/submit")
        post_dumped = network_path / post["req"]["sha256"]
        assert post_dumped.is_symlink()
        assert os.readlink(post_dumped) == cuckoo_utils.get_files_storage_path(post["req"]["sha256"])
        assert post_dumped.read_bytes() == POST_BODY

    def test_unanswered_request_is_reported(self, http_pcap, tmp_path):
        results = Pcap2(http_pcap, {}, str(tmp_path / "network")).run()
        orphan = next(flow for flow in results["http_ex"] if flow["uri"] == "/orphan")
        assert orphan["status"] == 0
        assert orphan["response"] == b""
        assert orphan["host"] == "orphan.example"

    def test_smtp_session(self, smtp_pcap, tmp_path):
        results = Pcap2(smtp_pcap, {}, str(tmp_path / "network")).run()
        assert len(results["smtp_ex"]) == 1
        flow = results["smtp_ex"][0]

        # reported client -> server, even though the server sends the first frame
        assert flow["src"] == CLIENT_IP
        assert flow["sport"] == 52000
        assert flow["dst"] == SMTP_SERVER_IP
        assert flow["dport"] == 25
        assert flow["resp"]["banner"].startswith("220 mail.evil.test")

        req = flow["req"]
        assert req["hostname"] == "workstation"
        assert req["mail_from"] == "<attacker@evil.test>"
        assert req["mail_to"] == ["<victim@corp.test>"]
        assert req["auth_type"] == "LOGIN"
        # tshark reports the AUTH LOGIN credentials base64 encoded
        assert req["username"] == "attacker@evil.test"
        assert req["password"] == "SuperSecret123"
        assert req["headers"]["Subject"] == "exfil"
        assert req["mail_body"] == MAIL_BODY.decode()

    def test_tshark_failure_is_logged(self, http_pcap, tmp_path, caplog):
        """An invalid field must surface in the log instead of looking like an empty pcap."""
        pcap2 = Pcap2(http_pcap, {}, str(tmp_path / "network"))
        packets = list(pcap2._iter_packets("http", ("frame.time_epoch", "not.a.real.field"), None))
        assert packets == []
        assert any("tshark exited with" in record.message for record in caplog.records)

    def test_keylog_is_written_and_removed(self, http_pcap, tmp_path):
        tlsmaster = {(b"\x01" * 32, b"\x02" * 32): b"\x03" * 48}
        pcap2 = Pcap2(http_pcap, tlsmaster, str(tmp_path / "network"))
        keylog_path = pcap2._write_keylog()
        try:
            with open(keylog_path) as f:
                content = f.read()
            assert content == f"CLIENT_RANDOM {'01' * 32} {'03' * 48}\n"
        finally:
            os.unlink(keylog_path)

    def test_missing_pcap_returns_empty(self, tmp_path):
        assert Pcap2(str(tmp_path / "nope.pcap"), {}, str(tmp_path / "network")).run() == {}

    def test_tshark_timeout_kills_stalled_process(self, http_pcap, tmp_path, monkeypatch, caplog):
        """A hung tshark must be killed by self.timeout while streaming stdout."""
        real_popen = subprocess.Popen

        def slow_popen(_cmd, **kwargs):
            return real_popen([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)

        monkeypatch.setattr(subprocess, "Popen", slow_popen)
        pcap2 = Pcap2(http_pcap, {}, str(tmp_path / "network"))
        pcap2.timeout = 0.2
        packets = list(pcap2._iter_packets("http", Pcap2.METADATA_FIELDS, None))
        assert packets == []
        assert any("tshark timed out after" in record.message for record in caplog.records)

    def test_http_100_continue_does_not_desync_response_pairing(self, tmp_path):
        """An interim 100 Continue response must not consume the request or emit an UNKNOWN flow."""
        req = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 11\r\n\r\n"
        resp100 = b"HTTP/1.1 100 Continue\r\n\r\n"
        body = b"hello world"
        resp200 = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
        frames = [
            _frame(CLIENT_IP, SERVER_IP, 12345, 80, 1, 1, req),
            _frame(SERVER_IP, CLIENT_IP, 80, 12345, 1, 1 + len(req), resp100),
            _frame(CLIENT_IP, SERVER_IP, 12345, 80, 1 + len(req), 1 + len(resp100), body),
            _frame(SERVER_IP, CLIENT_IP, 80, 12345, 1 + len(resp100), 1 + len(req) + len(body), resp200),
        ]
        pcap_path = _write_pcap(str(tmp_path / "http_100.pcap"), frames)
        network_path = tmp_path / "network"
        results = Pcap2(pcap_path, {}, str(network_path)).run()

        assert len(results["http_ex"]) == 1
        flow = results["http_ex"][0]
        assert flow["method"] == "POST"
        assert flow["uri"] == "/upload"
        assert flow["status"] == 200
        assert (network_path / flow["req"]["sha256"]).read_bytes() == body
        assert (network_path / flow["resp"]["sha256"]).read_bytes() == b"OK"

    def test_http_pipelined_requests_and_responses_in_single_segment(self, tmp_path):
        """Multiple pipelined HTTP requests/responses in one TCP segment must all be extracted cleanly."""
        reqs = (
            b"GET /one HTTP/1.1\r\nHost: one.example\r\nUser-Agent: ua1\r\n\r\n"
            b"POST /two HTTP/1.1\r\nHost: two.example\r\nContent-Length: 3\r\n\r\nabc"
        )
        resps = (
            b"HTTP/1.1 200 OK\r\nServer: s1\r\nContent-Length: 3\r\n\r\nONE"
            b"HTTP/1.1 404 Not Found\r\nServer: s2\r\nContent-Length: 3\r\n\r\nTWO"
        )
        frames = [
            _frame(CLIENT_IP, SERVER_IP, 12345, 80, 1, 1, reqs),
            _frame(SERVER_IP, CLIENT_IP, 80, 12345, 1, 1 + len(reqs), resps),
        ]
        pcap_path = _write_pcap(str(tmp_path / "http_pipe.pcap"), frames)
        network_path = tmp_path / "network"
        results = Pcap2(pcap_path, {}, str(network_path)).run()

        assert len(results["http_ex"]) == 2
        f1, f2 = results["http_ex"]
        assert (f1["method"], f1["host"], f1["uri"], f1["status"]) == ("GET", "one.example", "/one", 200)
        assert f1["request"] == b"GET /one HTTP/1.1\r\nHost: one.example\r\nUser-Agent: ua1\r\n"
        assert f1["response"] == b"HTTP/1.1 200 OK\r\nServer: s1\r\nContent-Length: 3\r\n"
        assert (network_path / f1["resp"]["sha256"]).read_bytes() == b"ONE"

        assert (f2["method"], f2["host"], f2["uri"], f2["status"]) == ("POST", "two.example", "/two", 404)
        assert f2["request"] == b"POST /two HTTP/1.1\r\nHost: two.example\r\nContent-Length: 3\r\n"
        assert f2["response"] == b"HTTP/1.1 404 Not Found\r\nServer: s2\r\nContent-Length: 3\r\n"
        assert (network_path / f2["req"]["sha256"]).read_bytes() == b"abc"
        assert (network_path / f2["resp"]["sha256"]).read_bytes() == b"TWO"

    def test_smtp_auth_plain_pipelined_quit_and_multi_message(self, tmp_path):
        """AUTH PLAIN credentials, pipelined .\\r\\nQUIT\\r\\n, and multiple emails on one stream."""
        auth_plain = base64.b64encode(b"\x00attacker@evil.test\x00SuperSecret123")
        mail1 = b"From: a@evil.test\r\nTo: b@corp.test\r\nSubject: m1\r\n\r\nBody 1\r\n..dot\r\n.\r\n"
        mail2 = b"From: a@evil.test\r\nTo: c@corp.test\r\nSubject: m2\r\n\r\nBody 2\r\n.\r\nQUIT\r\n"
        conversation = [
            (False, b"220 mail.evil.test ESMTP\r\n"),
            (True, b"EHLO workstation\r\n"),
            (False, b"250-mail.evil.test\r\n250 AUTH PLAIN LOGIN\r\n"),
            (True, b"AUTH PLAIN " + auth_plain + b"\r\n"),
            (False, b"235 2.7.0 Ok\r\n"),
            (True, b"MAIL FROM:<a@evil.test>\r\n"),
            (False, b"250 Ok\r\n"),
            (True, b"RCPT TO:<b@corp.test>\r\n"),
            (False, b"250 Ok\r\n"),
            (True, b"DATA\r\n"),
            (False, b"354 Go ahead\r\n"),
            (True, mail1),
            (False, b"250 Queued 1\r\n"),
            (True, b"MAIL FROM:<a@evil.test>\r\n"),
            (False, b"250 Ok\r\n"),
            (True, b"RCPT TO:<c@corp.test>\r\n"),
            (False, b"250 Ok\r\n"),
            (True, b"DATA\r\n"),
            (False, b"354 Go ahead\r\n"),
            (True, mail2),
            (False, b"250 Queued 2\r\n221 Bye\r\n"),
        ]
        frames = []
        cseq = sseq = 1
        for from_client, payload in conversation:
            if from_client:
                frames.append(_frame(CLIENT_IP, SMTP_SERVER_IP, 52001, 25, cseq, sseq, payload))
                cseq += len(payload)
            else:
                frames.append(_frame(SMTP_SERVER_IP, CLIENT_IP, 25, 52001, sseq, cseq, payload))
                sseq += len(payload)

        pcap_path = _write_pcap(str(tmp_path / "smtp_multi.pcap"), frames)
        results = Pcap2(pcap_path, {}, str(tmp_path / "network")).run()

        assert len(results["smtp_ex"]) == 2
        tx1, tx2 = results["smtp_ex"]
        assert tx1["req"]["auth_type"] == "PLAIN"
        assert tx1["req"]["username"] == "attacker@evil.test"
        assert tx1["req"]["password"] == "SuperSecret123"
        assert tx1["req"]["mail_to"] == ["<b@corp.test>"]
        assert tx1["req"]["headers"]["Subject"] == "m1"
        assert tx1["req"]["mail_body"] == "Body 1\r\n.dot\r\n"

        assert tx2["req"]["mail_to"] == ["<c@corp.test>"]
        assert tx2["req"]["headers"]["Subject"] == "m2"
        assert tx2["req"]["mail_body"] == "Body 2\r\n"

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl is not installed")
    def test_smtps_tls_wrapped_body_is_reconstructed(self, tmp_path):
        """TLS-wrapped SMTP sessions reconstruct both headers and mail_body via IMF export."""
        cert_file = str(tmp_path / "cert.pem")
        key_file = str(tmp_path / "key.pem")
        keylog_file = str(tmp_path / "sslkeys.log")
        pcap_path = str(tmp_path / "smtps.pcap")
        subprocess.check_call(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_file,
                "-out",
                cert_file,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=mail.evil.test",
            ],
            stderr=subprocess.DEVNULL,
        )

        srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        srv_ctx.load_cert_chain(cert_file, key_file)

        cli_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cli_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        cli_ctx.check_hostname = False
        cli_ctx.verify_mode = ssl.CERT_NONE
        cli_ctx.keylog_filename = keylog_file

        c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        cli_ssl = cli_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname="mail.evil.test")
        srv_ssl = srv_ctx.wrap_bio(s_in, s_out, server_side=True)

        frames = []
        cseq = sseq = 1

        def flush_bios():
            nonlocal cseq, sseq
            while True:
                progressed = False
                d = c_out.read()
                if d:
                    frames.append(_frame(CLIENT_IP, SMTP_SERVER_IP, 52002, 465, cseq, sseq, d))
                    cseq += len(d)
                    s_in.write(d)
                    progressed = True
                d = s_out.read()
                if d:
                    frames.append(_frame(SMTP_SERVER_IP, CLIENT_IP, 465, 52002, sseq, cseq, d))
                    sseq += len(d)
                    c_in.write(d)
                    progressed = True
                if not progressed:
                    break

        for _ in range(10):
            for obj in (cli_ssl, srv_ssl):
                try:
                    obj.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                flush_bios()

        conv = [
            (False, b"220 mail.evil.test ESMTP\r\n"),
            (True, b"EHLO client\r\n"),
            (False, b"250 Ok\r\n"),
            (True, b"MAIL FROM:<a@evil.test>\r\n"),
            (False, b"250 Ok\r\n"),
            (True, b"RCPT TO:<b@corp.test>\r\n"),
            (False, b"250 Ok\r\n"),
            (True, b"DATA\r\n"),
            (False, b"354 Go ahead\r\n"),
            (True, b"From: a@evil.test\r\nTo: b@corp.test\r\nSubject: tls-exfil\r\n\r\nSecret TLS body\r\n.\r\n"),
            (False, b"250 Queued\r\n"),
            (True, b"QUIT\r\n"),
        ]
        for from_client, msg in conv:
            if from_client:
                cli_ssl.write(msg)
                flush_bios()
                srv_ssl.read(4096)
            else:
                srv_ssl.write(msg)
                flush_bios()
                cli_ssl.read(4096)

        _write_pcap(pcap_path, frames)
        results = Pcap2(pcap_path, {}, str(tmp_path / "network"), keylog_files=[keylog_file]).run()

        assert len(results["smtp_ex"]) == 1
        req = results["smtp_ex"][0]["req"]
        assert req["headers"]["Subject"] == "tls-exfil"
        assert req["mail_body"] == "Secret TLS body\r\n"

        # Prepend a cleartext SMTP stream with Subject "zzz-clear" to verify IMF export
        # alignment when both cleartext and TLS SMTP streams exist in the same capture.
        clear_frames = []
        ccseq = csseq = 1
        for from_client, payload in [
            (False, b"220 mail.evil.test ESMTP\r\n"),
            (True, b"EHLO clear\r\n"),
            (False, b"250 Ok\r\n"),
            (True, b"MAIL FROM:<c@evil.test>\r\n"),
            (False, b"250 Ok\r\n"),
            (True, b"RCPT TO:<d@corp.test>\r\n"),
            (False, b"250 Ok\r\n"),
            (True, b"DATA\r\n"),
            (False, b"354 Go ahead\r\n"),
            (True, b"From: c@evil.test\r\nTo: d@corp.test\r\nSubject: zzz-clear\r\n\r\nCleartext body\r\n.\r\n"),
            (False, b"250 Queued\r\n"),
        ]:
            if from_client:
                clear_frames.append(_frame(CLIENT_IP, SMTP_SERVER_IP, 52000, 25, ccseq, csseq, payload))
                ccseq += len(payload)
            else:
                clear_frames.append(_frame(SMTP_SERVER_IP, CLIENT_IP, 25, 52000, csseq, ccseq, payload))
                csseq += len(payload)

        mixed_smtp_pcap = _write_pcap(str(tmp_path / "smtp_mixed_tls.pcap"), clear_frames + frames)
        mixed_res = Pcap2(mixed_smtp_pcap, {}, str(tmp_path / "network2"), keylog_files=[keylog_file]).run()
        assert len(mixed_res["smtp_ex"]) == 2
        by_subj = {entry["req"]["headers"]["Subject"]: entry["req"]["mail_body"] for entry in mixed_res["smtp_ex"]}
        assert by_subj == {
            "zzz-clear": "Cleartext body\r\n",
            "tls-exfil": "Secret TLS body\r\n",
        }

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl is not installed")
    def test_https_tls12_and_pcapng_dsb_decryption(self, tmp_path):
        """HTTPS over TLS 1.2 is decrypted into https_ex via tlsdump.log or embedded pcapng DSB."""
        cert_file = str(tmp_path / "cert.pem")
        key_file = str(tmp_path / "key.pem")
        keylog_file = str(tmp_path / "sslkeys.log")
        pcap_path = str(tmp_path / "https.pcap")
        subprocess.check_call(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_file,
                "-out",
                cert_file,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=secure.example.test",
            ],
            stderr=subprocess.DEVNULL,
        )

        srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        srv_ctx.load_cert_chain(cert_file, key_file)

        cli_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cli_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        cli_ctx.check_hostname = False
        cli_ctx.verify_mode = ssl.CERT_NONE
        cli_ctx.keylog_filename = keylog_file

        c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        cli_ssl = cli_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname="secure.example.test")
        srv_ssl = srv_ctx.wrap_bio(s_in, s_out, server_side=True)

        frames = []
        cseq = sseq = 1

        def flush_bios():
            nonlocal cseq, sseq
            while True:
                progressed = False
                d = c_out.read()
                if d:
                    frames.append(_frame(CLIENT_IP, SERVER_IP, 54000, 443, cseq, sseq, d))
                    cseq += len(d)
                    s_in.write(d)
                    progressed = True
                d = s_out.read()
                if d:
                    frames.append(_frame(SERVER_IP, CLIENT_IP, 443, 54000, sseq, cseq, d))
                    sseq += len(d)
                    c_in.write(d)
                    progressed = True
                if not progressed:
                    break

        for _ in range(10):
            for obj in (cli_ssl, srv_ssl):
                try:
                    obj.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                flush_bios()

        req_bytes = (
            b"POST /gate HTTP/1.1\r\n"
            b"Host: secure.example.test\r\n"
            b"User-Agent: test-agent/1.0\r\n"
            b"Content-Length: " + str(len(POST_BODY)).encode() + b"\r\n\r\n" + POST_BODY
        )
        resp_bytes = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(RESPONSE_BODY)).encode() + b"\r\n\r\n" + RESPONSE_BODY
        )

        cli_ssl.write(req_bytes)
        flush_bios()
        srv_ssl.read(65536)

        srv_ssl.write(resp_bytes)
        flush_bios()
        cli_ssl.read(65536)

        _write_pcap(pcap_path, frames)

        # Convert NSS keylog line into CAPE tlsdump.log format to test _write_keylog parsing
        tlsdump_file = tmp_path / "tlsdump.log"
        with open(keylog_file) as kf:
            _, crand, msecret = next(
                line.split() for line in kf.read().splitlines() if line.startswith("CLIENT_RANDOM")
            )
        tlsdump_file.write_text(
            f"client_random: {crand}, server_random: {'aa' * 32}, master_secret: {msecret}\n"
        )

        net1 = tmp_path / "net_tlsdump"
        res1 = Pcap2(pcap_path, {}, str(net1), keylog_files=[str(tlsdump_file)]).run()
        assert len(res1["https_ex"]) == 1
        flow = res1["https_ex"][0]
        assert (flow["protocol"], flow["method"], flow["host"], flow["uri"], flow["status"]) == (
            "https",
            "POST",
            "secure.example.test",
            "/gate",
            200,
        )
        assert (net1 / flow["req"]["sha256"]).read_bytes() == POST_BODY
        assert (net1 / flow["resp"]["sha256"]).read_bytes() == RESPONSE_BODY

        if shutil.which("editcap"):
            pcapng_path = str(tmp_path / "https_dsb.pcapng")
            subprocess.check_call(["editcap", "--inject-secrets", f"tls,{keylog_file}", pcap_path, pcapng_path])
            net2 = tmp_path / "net_dsb"
            res2 = Pcap2(pcapng_path, {}, str(net2)).run()
            assert len(res2["https_ex"]) == 1
            flow2 = res2["https_ex"][0]
            assert (flow2["protocol"], flow2["method"], flow2["host"], flow2["uri"], flow2["status"]) == (
                "https",
                "POST",
                "secure.example.test",
                "/gate",
                200,
            )
            assert (net2 / flow2["req"]["sha256"]).read_bytes() == POST_BODY
            assert (net2 / flow2["resp"]["sha256"]).read_bytes() == RESPONSE_BODY

    @pytest.mark.skipif(not shutil.which("openssl"), reason="openssl is not installed")
    def test_https_tls13_and_http2_decryption(self, tmp_path):
        """HTTP/2 over TLS 1.3 (ALPN h2) with TLS 1.3 secrets in tlsdump.log is decrypted into https_ex."""
        cert_file = str(tmp_path / "cert.pem")
        key_file = str(tmp_path / "key.pem")
        keylog_file = str(tmp_path / "tlsdump.log")
        pcap_path = str(tmp_path / "h2_tls13.pcap")
        subprocess.check_call(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_file,
                "-out",
                cert_file,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=h2.example.test",
            ],
            stderr=subprocess.DEVNULL,
        )

        srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        srv_ctx.load_cert_chain(cert_file, key_file)
        srv_ctx.set_alpn_protocols(["h2"])

        cli_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cli_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        cli_ctx.check_hostname = False
        cli_ctx.verify_mode = ssl.CERT_NONE
        cli_ctx.set_alpn_protocols(["h2"])
        cli_ctx.keylog_filename = keylog_file

        c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        cli_ssl = cli_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname="h2.example.test")
        srv_ssl = srv_ctx.wrap_bio(s_in, s_out, server_side=True)

        frames = []
        cseq = sseq = 1

        def flush_bios():
            nonlocal cseq, sseq
            while True:
                progressed = False
                d = c_out.read()
                if d:
                    frames.append(_frame(CLIENT_IP, SERVER_IP, 54001, 443, cseq, sseq, d))
                    cseq += len(d)
                    s_in.write(d)
                    progressed = True
                d = s_out.read()
                if d:
                    frames.append(_frame(SERVER_IP, CLIENT_IP, 443, 54001, sseq, cseq, d))
                    sseq += len(d)
                    c_in.write(d)
                    progressed = True
                if not progressed:
                    break

        for _ in range(10):
            for obj in (cli_ssl, srv_ssl):
                try:
                    obj.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                flush_bios()

        def h2_frame(ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
            length = len(payload)
            return (
                bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF, ftype, flags])
                + struct.pack("!I", stream_id)
                + payload
            )

        def hpack_lit(name: bytes, val: bytes) -> bytes:
            return b"\x00" + bytes([len(name)]) + name + bytes([len(val)]) + val

        req_hdrs = (
            hpack_lit(b":method", b"POST")
            + hpack_lit(b":scheme", b"https")
            + hpack_lit(b":authority", b"h2.example.test")
            + hpack_lit(b":path", b"/v2/gate")
            + hpack_lit(b"user-agent", b"h2-agent/2.0")
        )
        cli_ssl.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + h2_frame(4, 0, 0) + h2_frame(1, 0x04, 1, req_hdrs))
        flush_bios()
        srv_ssl.read(65536)

        cli_ssl.write(h2_frame(0, 0x00, 1, b"part1-"))
        flush_bios()
        srv_ssl.read(65536)

        cli_ssl.write(h2_frame(0, 0x01, 1, b"part2"))
        flush_bios()
        srv_ssl.read(65536)

        resp_hdrs = (
            hpack_lit(b":status", b"200")
            + hpack_lit(b"server", b"h2srv")
            + hpack_lit(b"content-encoding", b"gzip")
        )
        gz_resp = gzip.compress(b"decrypted-http2-response")
        srv_ssl.write(
            h2_frame(4, 0, 0)
            + h2_frame(4, 0x01, 0)
            + h2_frame(1, 0x04, 1, resp_hdrs)
            + h2_frame(0, 0x01, 1, gz_resp)
        )
        flush_bios()
        cli_ssl.read(65536)

        _write_pcap(pcap_path, frames)
        net_dir = tmp_path / "net_h2"
        results = Pcap2(pcap_path, {}, str(net_dir), keylog_files=[keylog_file]).run()

        assert len(results["https_ex"]) == 1
        flow = results["https_ex"][0]
        assert (flow["protocol"], flow["method"], flow["host"], flow["uri"], flow["status"]) == (
            "https",
            "POST",
            "h2.example.test",
            "/v2/gate",
            200,
        )
        assert flow["request"] == b"POST /v2/gate HTTP/2\r\nHost: h2.example.test\r\nuser-agent: h2-agent/2.0\r\n"
        assert flow["response"].startswith(b"HTTP/2 200\r\n")
        assert (net_dir / flow["req"]["sha256"]).read_bytes() == b"part1-part2"
        assert (net_dir / flow["resp"]["sha256"]).read_bytes() == b"decrypted-http2-response"



