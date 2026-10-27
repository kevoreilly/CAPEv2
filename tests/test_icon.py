# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import pathlib
from unittest.mock import MagicMock

import pytest
from tcr_misc import get_sample

from lib.cuckoo.common.icon import PEGroupIconDir


@pytest.fixture
def sample():
    def get_binary_data(sample_location):
        with open(sample_location, mode="rb") as f:
            return f.read()

    def _grab_sample(sample_hash):
        sample_location = pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        get_sample(hash=sample_hash, download_location=sample_location)
        return get_binary_data(sample_location)

    return _grab_sample


class TestPEGroupIconDir:
    # Sample taken from https://www.scintilla.org/wscite32_446.zip
    @pytest.mark.skip(reason="TODO")
    def test_init(self, sample):
        return_obj = PEGroupIconDir(data=sample("438117c7bd53653b3113903bcdb8bd369904a152b524b4676b18a626c2b60e82"))
        assert len(return_obj.icons) == 3

    @pytest.mark.skip(reason="TODO")
    def test_get_icon_file(self, sample):
        return_obj = PEGroupIconDir(data=sample("438117c7bd53653b3113903bcdb8bd369904a152b524b4676b18a626c2b60e82"))
        assert (
            return_obj.get_icon_file(idx=0, data=b"FOOBAR")
            == b"\x00\x00\x01\x00\x01\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x16\x00\x00\x00FOOBAR"
        )


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("buffer is not large enough"),
        OSError("Unsupported BMP header type (1852795252)"),
    ],
)
def test_get_icon_info_logs_debug_not_error(caplog, monkeypatch, exc):
    import pefile

    import lib.cuckoo.common.integrations.parse_pe as parse_pe

    pe_helper = parse_pe.PortableExecutable("/tmp/fake.exe")

    fake_entry = MagicMock()
    fake_entry.id = 1
    fake_entry.directory.entries = [MagicMock(data=MagicMock(struct=MagicMock(OffsetToData=0, Size=16)))]

    fake_group_dir = MagicMock()
    fake_group_dir.id = pefile.RESOURCE_TYPE["RT_GROUP_ICON"]
    fake_group_dir.directory.entries = [fake_entry]

    fake_icon_dir = MagicMock()
    fake_icon_dir.id = pefile.RESOURCE_TYPE["RT_ICON"]
    fake_icon_dir.directory.entries = [fake_entry]

    fake_pe = MagicMock()
    fake_pe.DIRECTORY_ENTRY_RESOURCE.entries = [fake_group_dir, fake_icon_dir]
    fake_pe.get_memory_mapped_image.return_value = b"\x00" * 64

    fake_icon_meta = MagicMock(bWidth=32, bHeight=32, wBitCount=32, nID=1)
    fake_peicon = MagicMock()
    fake_peicon.icons = [fake_icon_meta]
    fake_peicon.get_icon_file.return_value = b"bad_icon_bytes"

    monkeypatch.setattr(parse_pe, "PEGroupIconDir", lambda data: fake_peicon)
    monkeypatch.setattr(parse_pe.Image, "open", MagicMock(side_effect=exc))

    with caplog.at_level(logging.DEBUG, logger=parse_pe.__name__):
        res = pe_helper.get_icon_info(fake_pe)

    assert res == (None, None, None, None)
    assert not any(r.levelname == "ERROR" for r in caplog.records)


def test_extract_pkcs7_der_bytes_and_get_digital_signers():
    import binascii
    import datetime
    import struct
    import warnings
    from unittest.mock import MagicMock

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.utils import CryptographyDeprecationWarning
    from cryptography.x509.oid import NameOID
    import pefile

    import lib.cuckoo.common.integrations.parse_pe as parse_pe

    # Generate synthetic self-signed X.509 certificate
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Signer"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(123456789)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )

    pkcs7_der = pkcs7.serialize_certificates([cert], serialization.Encoding.DER)
    assert len(pkcs7_der) > 0
    assert pkcs7_der[0] == 0x30

    header_offset = 128
    prefix_data = b"\x90" * header_offset

    raw_cert_len = len(pkcs7_der)
    total_entry_len = 8 + raw_cert_len
    pad_len = (8 - (total_entry_len % 8)) % 8
    if pad_len == 0:
        pad_len = 8
    total_entry_len += pad_len
    padding_bytes = b"\x00" * pad_len
    overlay_bytes = b"OVERLAY_PAYLOAD_EXTRA_BYTES_1234567890"

    win_cert_header = struct.pack("<IHH", total_entry_len, 0x0200, 0x0002)
    win_cert_blob = win_cert_header + pkcs7_der + padding_bytes
    pe_data = prefix_data + win_cert_blob + overlay_bytes

    # 1. Test _extract_pkcs7_der_bytes directly
    extracted = parse_pe._extract_pkcs7_der_bytes(pe_data, address=header_offset, size=total_entry_len)
    assert extracted == pkcs7_der

    extracted_with_overlay_in_size = parse_pe._extract_pkcs7_der_bytes(
        pe_data, address=header_offset, size=total_entry_len + len(overlay_bytes)
    )
    assert extracted_with_overlay_in_size == pkcs7_der

    # 2. Test get_digital_signers with mock PE
    pe_helper = parse_pe.PortableExecutable("/tmp/fake_signed.exe")
    fake_pe = MagicMock()
    dir_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    fake_dir_entry = MagicMock(VirtualAddress=header_offset, Size=total_entry_len)

    fake_pe.OPTIONAL_HEADER.DATA_DIRECTORY = [MagicMock()] * (dir_index + 1)
    fake_pe.OPTIONAL_HEADER.DATA_DIRECTORY[dir_index] = fake_dir_entry
    fake_pe.write.return_value = pe_data

    with warnings.catch_warnings(record=True) as recorded_warnings:
        warnings.simplefilter("always")
        signers = pe_helper.get_digital_signers(fake_pe)

    discouraged_warnings = [
        w for w in recorded_warnings
        if issubclass(w.category, (UserWarning, CryptographyDeprecationWarning))
    ]
    assert discouraged_warnings == []

    assert len(signers) == 1
    signer = signers[0]
    expected_md5 = binascii.hexlify(cert.fingerprint(hashes.MD5())).decode()
    expected_sha1 = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode()
    expected_sha256 = binascii.hexlify(cert.fingerprint(hashes.SHA256())).decode()

    assert signer["md5_fingerprint"] == expected_md5
    assert signer["sha1_fingerprint"] == expected_sha1
    assert signer["sha256_fingerprint"] == expected_sha256
    assert signer["serial_number"] == str(cert.serial_number)
    assert signer["not_before"] == cert.not_valid_before_utc.isoformat()
    assert signer["not_after"] == cert.not_valid_after_utc.isoformat()
    assert signer["subject_commonName"] == "Test Signer"
    assert signer["issuer_commonName"] == "Test Signer"


