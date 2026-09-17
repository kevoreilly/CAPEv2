"""End-to-end tests for the tshark based Pcap2 parser.

The pcaps are built byte by byte so the expected payloads are known exactly, and tshark is
invoked for real: mocking its JSON output only proves that the mock matches the parser.
"""

import base64
import os
import shutil
import struct

import pytest

from modules.processing.network import Pcap2

pytestmark = pytest.mark.skipif(not shutil.which("tshark"), reason="tshark is not installed")

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
        assert dumped.read_bytes() == RESPONSE_BODY
        assert get["resp"]["preview"][0].endswith("|MZ..........bina|")

        post = next(flow for flow in results["http_ex"] if flow["uri"] == "/submit")
        assert (network_path / post["req"]["sha256"]).read_bytes() == POST_BODY

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
