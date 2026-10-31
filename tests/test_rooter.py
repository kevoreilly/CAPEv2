import errno
import json
import logging

from utils.rooter import send_response


def test_send_response_sends_json(mocker):
    server = mocker.MagicMock()
    send_response(server, "out", None, "/tmp/reply.sock")
    payload, addr = server.sendto.call_args.args
    assert json.loads(payload) == {"output": "out", "exception": None}
    assert addr == "/tmp/reply.sock"


def test_send_response_handles_unlinked_client_socket(mocker, caplog):
    """The client timed out and removed its reply socket: log a warning, do not crash the rooter loop."""
    server = mocker.MagicMock()
    server.sendto.side_effect = FileNotFoundError(errno.ENOENT, "No such file or directory")

    with caplog.at_level(logging.WARNING):
        send_response(server, "", None, "/tmp/unlinked.sock")

    records = [r for r in caplog.records if "Failed to send response to /tmp/unlinked.sock" in r.message]
    assert len(records) == 1
    assert records[0].exc_info is None
