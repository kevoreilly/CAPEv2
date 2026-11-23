import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from lib.cuckoo.common.integrations import parse_rdp


def _build_test_chain(dns_name="rdp.example.com", ip_addr="10.0.0.5", digital_signature=True):
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = rsa.generate_private_key(65537, 2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unit Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(65537, 2048)
    san_entries = [x509.DNSName(dns_name), x509.IPAddress(ipaddress.ip_address(ip_addr))]
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_cert, leaf_cert


def test_validate_sig_verifies_dns_ip_and_port(tmp_path):
    ca_cert, leaf_cert = _build_test_chain()
    bundle = tmp_path / "ca.pem"
    bundle.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    res = parse_rdp.validate_sig("rdp.example.com:3389", "10.0.0.5:3389", [leaf_cert], ca_bundle_path=str(bundle))
    assert res["can_sign"] is True
    assert res["main_valid"] is True
    assert res["alt_valid"] is True
    assert res["valid"] is True
    assert res["general_error"] == ""
    assert res["validation_errors"] == []


def test_validate_sig_flags_untrusted_and_missing_digital_signature(tmp_path):
    ca_cert, leaf_cert = _build_test_chain(digital_signature=False)
    other_ca, _ = _build_test_chain(dns_name="other.example.com")
    bundle = tmp_path / "other_ca.pem"
    bundle.write_bytes(other_ca.public_bytes(serialization.Encoding.PEM))

    res = parse_rdp.validate_sig("rdp.example.com", "", [leaf_cert], ca_bundle_path=str(bundle))
    assert res["can_sign"] is False
    assert "digital_signature" in res["usage_error"]
    assert res["main_valid"] is False
    assert res["valid"] is False
    assert len(res["validation_errors"]) == 1


def test_parse_rdp_file_handles_unsigned_without_alternate_address(tmp_path):
    rdp_file = tmp_path / "sample.rdp"
    rdp_file.write_text("full address:s:rdp.example.com:3389\nusername:s:alice\n", encoding="utf-8")

    parsed = parse_rdp.parse_rdp_file(str(rdp_file))
    assert parsed["full_address"] == "rdp.example.com:3389"
    assert parsed["signscope_but_missing_sig"] is False
