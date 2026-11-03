# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from pathlib import Path

from lib.cuckoo.common.pcap_utils import append_file_contents_to_file


def test_append_file_contents_to_file_binary(tmp_path: Path):
    """Ensure binary data with non-UTF-8 bytes is appended correctly."""
    src_file = tmp_path / "src.bin"
    dst_file = tmp_path / "dst.bin"

    # Bytes that are invalid UTF-8 sequences (0x81, 0xfe, 0xff)
    non_utf8_payload = b"\x81\xfe\xff\x00\xaa\xbb\xcc\xdd"
    initial_content = b"INITIAL_HEADER\n"

    dst_file.write_bytes(initial_content)
    src_file.write_bytes(non_utf8_payload)

    append_file_contents_to_file(src_file, dst_file)

    assert dst_file.read_bytes() == initial_content + non_utf8_payload


def test_append_file_contents_to_file_creates_dest_if_missing(tmp_path: Path):
    """Ensure destination file is created if it does not already exist."""
    src_file = tmp_path / "src.bin"
    dst_file = tmp_path / "dst_missing.bin"

    payload = b"\x81\xfe\xff"
    src_file.write_bytes(payload)

    append_file_contents_to_file(src_file, dst_file)

    assert dst_file.read_bytes() == payload
