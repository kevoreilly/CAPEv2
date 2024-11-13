import argparse
import base64
import datetime
import json
import logging
import sys
from contextlib import suppress
from hashlib import sha1, sha256
from struct import unpack

MISSED_DEPS = False
try:
    import mscerts
    from asn1crypto import pem, x509
    from certvalidator import CertificateValidator, ValidationContext
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import ExtensionOID
except ImportError:
    print("pip3 install certvalidator asn1crypto mscerts")
    MISSED_DEPS = True
try:
    import re2 as re
except ImportError:
    import re

property_patterns = {
    "alternate_full_address": re.compile(r"alternate\s+full\s+address\s*:\s*s\s*:\s*(.*)", re.I),
    "alternate_shell": re.compile(r"alternate\s+shell\s*:\s*s\s*:\s*(.*)", re.I),
    "authentication_level": re.compile(r"authentication\s+level\s*:\s*i\s*:\s*(\d+)", re.I),
    "autoreconnection_enabled": re.compile(r"autoreconnection\s*enabled\s*:\s*i\s*:\s*(\d+)", re.I),
    "audiocapturemode": re.compile(r"audiocapturemode\s*:\s*i\s*:\s*(\d+)", re.I),
    "audiomode": re.compile(r"audiomode\s*:\s*i\s*:\s*(\d+)", re.I),
    "bandwidthautodetect": re.compile(r"bandwidthautodetect\s*:\s*i\s*:\s*(\d+)", re.I),
    "camerastoredirect": re.compile(r"camerastoredirect\s*:\s*s\s*:\s*(.*)", re.I),
    "compression": re.compile(r"compression\s*:\s*i\s*:\s*(\d+)", re.I),
    "disableconnectionsharing": re.compile(r"disableconnectionsharing\s*:\s*i\s*:\s*(\d+)", re.I),
    "drivestoredirect": re.compile(r"drivestoredirect\s*:\s*s\s*:\s*(.*)", re.I),
    "enablecredsspsupport": re.compile(r"enablecredsspsupport\s*:\s*i\s*:\s*(\d+)", re.I),
    "enablerdsaadauth": re.compile(r"enablerdsaadauth\s*:\s*i\s*:\s*(\d+)", re.I),
    "full_address": re.compile(r"full\s+address\s*:\s*s\s*:\s*(.*)", re.I),
    "gatewaycredentialssource": re.compile(r"gatewaycredentialssource\s*:\s*i\s*:\s*(\d+)", re.I),
    "gatewayhostname": re.compile(r"gatewayhostname\s*:\s*s\s*:\s*(.*)", re.I),
    "gatewayprofileusagemethod": re.compile(r"gatewayprofileusagemethod\s*:\s*i\s*:\s*(\d+)", re.I),
    "gatewayusagemethod": re.compile(r"gatewayusagemethod\s*:\s*i\s*:\s*(\d+)", re.I),
    "keyboardhook": re.compile(r"keyboardhook\s*:\s*i\s*:\s*(\d+)", re.I),
    "networkautodetect": re.compile(r"networkautodetect\s*:\s*i\s*:\s*(\d+)", re.I),
    "promptcredentialonce": re.compile(r"promptcredentialonce\s*:\s*i\s*:\s*(\d+)", re.I),
    "redirectclipboard": re.compile(r"redirectclipboard\s*:\s*i\s*:\s*(\d+)", re.I),
    "redirectcomports": re.compile(r"redirectcomports\s*:\s*i\s*:\s*(\d+)", re.I),
    "redirectlocation": re.compile(r"redirectlocation\s*:\s*i\s*:\s*(\d+)", re.I),
    "redirectprinters": re.compile(r"redirectprinters\s*:\s*i\s*:\s*(\d+)", re.I),
    "redirectsmartcards": re.compile(r"redirectsmartcards\s*:\s*i\s*:\s*(\d+)", re.I),
    "redirectwebauthn": re.compile(r"redirectwebauthn\s*:\s*i\s*:\s*(\d+)", re.I),
    "screen_mode_id": re.compile(r"screen mode id\s*:\s*i\s*:\s*(\d+)", re.I),
    "usbdevicestoredirect": re.compile(r"usbdevicestoredirect\s*:\s*s\s*:\s*(.*)", re.I),
    "videoplaybackmode": re.compile(r"videoplaybackmode\s*:\s*i\s*:\s*(\d+)", re.I),
    "remoteapplicationcmdline": re.compile(r"remoteapplicationcmdline\s*:\s*s\s*:\s*(.*)", re.I),
    "remoteapplicationexpandcmdline": re.compile(r"remoteapplicationexpandcmdline\s*:\s*i\s*:\s*(\d+)", re.I),
    "remoteapplicationexpandworkingdir": re.compile(r"remoteapplicationexpandworkingdir\s*:\s*i\s*:\s*(\d+)", re.I),
    "remoteapplicationfile": re.compile(r"remoteapplicationfile\s*:\s*s\s*:\s*(.*)", re.I),
    "remoteapplicationicon": re.compile(r"remoteapplicationicon\s*:\s*s\s*:\s*(.*)", re.I),
    "remoteapplicationmode": re.compile(r"remoteapplicationmode\s*:\s*i\s*:\s*(\d+)", re.I),
    "remoteapplicationname": re.compile(r"remoteapplicationname\s*:\s*s\s*:\s*(.*)", re.I),
    "remoteapplicationprogram": re.compile(r"remoteapplicationprogram\s*:\s*s\s*:\s*(.*)", re.I),
    "devicestoredirect": re.compile(r"devicestoredirect\s*:\s*s\s*:\s*(.*)", re.I),
    "signature": re.compile(r"signature\s*:\s*s\s*:\s*([A-Za-z0-9+/=\s]+)", re.I),
    "signscope": re.compile(r"signscope\s*:\s*s\s*:\s*(.*)", re.I),
}

log = logging.getLogger()


def validate_sig(hostname, alternate_faddress, pkcs7_certificates):
    sign_data = {
        "can_sign": False,
        "usage_error": "",
        "valid": False,
        "validation_errors": [],
        "general_error": "",
        "main_valid": False,
        "alt_valid": False,
    }
    if MISSED_DEPS:
        return sign_data
    try:
        ca_bundle_path = mscerts.where()
        trust_roots = []
        with open(ca_bundle_path, "rb") as f:
            pem_data = f.read()
            for _, _, der_bytes in pem.unarmor(pem_data, multiple=True):
                trust_roots.append(der_bytes)
        certs = [x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER)) for cert in pkcs7_certificates]
        context = ValidationContext(trust_roots=trust_roots)
        main_cert = certs[0]
        validator = CertificateValidator(main_cert, intermediate_certs=certs[1:], validation_context=context)
        try:
            validator.validate_usage({"digital_signature"})
            sign_data["can_sign"] = True
        except Exception as e:
            sign_data["usage_error"] = f"{e}"
        try:
            validator.validate_tls(hostname)
            sign_data["main_valid"] = True
        except Exception as e:
            sign_data["validation_errors"].append(f"{e}")
        if alternate_faddress:
            try:
                validator.validate_tls(alternate_faddress)
                sign_data["alt_valid"] = True
            except Exception as e:
                sign_data["validation_errors"].append(f"{e}")
        if sign_data["main_valid"] or sign_data["alt_valid"]:
            sign_data["valid"] = True
    except Exception as e:
        sign_data["general_error"] = f"{e}"
    return sign_data


def parse_rdp_file(file_path):
    rdp_properties = {}
    try:
        content = ""
        encoding = "utf-8"
        with open(file_path, "rb") as f:
            raw = f.read(4)
            if raw.startswith(b"\xff\xfe\x00\x00"):
                encoding = "utf-32-le"
            elif raw.startswith(b"\x00\x00\xfe\xff"):
                encoding = "utf-32-be"
            elif raw.startswith(b"\xfe\xff"):
                encoding = "utf-16-be"
            elif raw.startswith(b"\xff\xfe"):
                encoding = "utf-16-le"
            elif raw.startswith(b"\xef\xbb\xbf"):
                encoding = "utf-8-sig"

        with open(file_path, "r", encoding=encoding, errors="ignore") as f:
            content = f.read()
        if content and re.search(r"full\s+address\s*:\s*s\s*:", content, re.I):
            for line in content.splitlines():
                for prop, pattern in property_patterns.items():
                    match = pattern.search(line)
                    if match:
                        value = match.group(1).strip()
                        if value != "":
                            rdp_properties[prop] = value
        else:
            print("full_address is a required field... what sort of nonsense are you trying to feed me?")
            return rdp_properties
        if "full_address" not in rdp_properties:
            print(
                "full_address is a required field but is not in parsed Properties what sort of nonsense are you trying to feed me?"
            )
            return rdp_properties
        rdp_properties["signscope_but_missing_sig"] = False
        if "signscope" in rdp_properties and "signature" not in rdp_properties:
            rdp_properties["signscope_but_missing_sig"] = True
        elif "signature" in rdp_properties and "signscope" in rdp_properties:
            rdp_properties["certificate_truncated_or_invalid"] = False
            signature_base64 = rdp_properties["signature"]
            rdp_properties["certificates"] = []
            rdp_properties["certificate_chain_len"] = 0
            signature_bytes = b""
            rdp_properties["certificate_truncated_or_invalid"] = True
            with suppress(Exception):
                signature_bytes = base64.b64decode(signature_base64.replace("\n", "").replace("\r", ""))
            size_bytes = signature_bytes[8:12]
            data_size = 0
            with suppress(Exception):
                data_size = unpack("<I", size_bytes)[0]
            try:
                if len(signature_bytes) < data_size:
                    rdp_properties["certificate_truncated_or_invalid"] = True
                signature_bytes = signature_bytes[12 : 12 + data_size]
                try:
                    if signature_bytes:
                        rdp_properties["signature_hex"] = signature_bytes.hex()
                        rdp_properties["signature_sha1"] = sha1(signature_bytes).hexdigest()
                        rdp_properties["signature_sha256"] = sha256(signature_bytes).hexdigest()
                        certs = pkcs7.load_der_pkcs7_certificates(signature_bytes)
                        rdp_properties["certificate_chain_validation"] = validate_sig(
                            f"{rdp_properties['full_address']}", f"{rdp_properties['alternate_full_address']}", certs
                        )
                        for cert in certs:
                            cert_info = {
                                "subject": cert.subject.rfc4514_string(),
                                "issuer": cert.issuer.rfc4514_string(),
                                "not_before": cert.not_valid_before_utc.isoformat(),
                                "not_after": cert.not_valid_after_utc.isoformat(),
                                "serial_number": str(cert.serial_number),
                                "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                                "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex(),
                            }
                            morris_day_and_the_utc_time = datetime.datetime.now(datetime.timezone.utc)
                            if cert.not_valid_before_utc <= morris_day_and_the_utc_time <= cert.not_valid_after_utc:
                                cert_info["cert_valid_date"] = True
                            else:
                                cert_info["cert_valid"] = False
                            san_values = []
                            with suppress(Exception):
                                san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                san_values = san_extension.value.get_values_for_type(cx509.DNSName)
                            cert_info["subject_alternative_names"] = san_values if san_values else None
                            rdp_properties["certificates"].append(cert_info)
                except Exception as e:
                    print(f"Error parsing certificate: {e}")
            except Exception as e:
                print(f"Error parsing certificate: {e}")
            rdp_properties["certificate_chain_len"] = len(rdp_properties["certificates"])
    except Exception as e:
        print(f"Error reading or parsing RDP file: {e}")

    return rdp_properties


def main():
    parser = argparse.ArgumentParser(
        description="DUMB RDP Props to JSON dump.. Cert parsing doesn't work Weird nonsense in these DER certs aside from 8 byte junk then 4 byte size header https://www.youtube.com/watch?v=ceR4TDuqE5A"
    )
    parser.add_argument("-i", "--input", required=True, help="Input RDP file path")
    parser.add_argument("-o", "--output", required=True, help="Output file path to save JSON results")
    args = parser.parse_args()

    rdp_properties = parse_rdp_file(args.input)
    if not rdp_properties:
        print("Failed to parse RDP file.")
        sys.exit(1)
    try:
        output = json.dumps(rdp_properties, indent=4)
        with open(args.output, "w") as outfile:
            outfile.write(output)
    except Exception as e:
        print(f"it went pear shaped..{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
