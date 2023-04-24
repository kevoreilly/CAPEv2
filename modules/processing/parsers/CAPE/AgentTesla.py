import re
import struct
import yara
import logging
log = logging.getLogger(__name__)

rule_source = '''
rule AgentTesla
{
    meta:
        author = "kevoreilly"
        description = "AgentTesla config extraction"
        cape_type = "AgentTesla Payload"
    strings:
        $decode = {06 91 06 61 20 [4] 61 D2 9C 06 17 58 0A 06 7E [4] 8E 69 FE 04 2D ?? 2A}
    condition:
        uint16(0) == 0x5A4D and any of them
}
'''

yara_rules = yara.compile(source=rule_source)

def extract_config(data):
    config_dict = {}

    matches = yara_rules.match(data=data)
    if not matches:
        return

    decode_offset = 0
    for match in matches:
        log.info("match.rule = %s", match.rule)
        if match.rule != "AgentTesla":
            continue
        for item in match.strings:
            if '$decode' in item[1]:
                decode_offset = int(item[0])

    if not decode_offset:
        return

    key = struct.unpack("B", data[decode_offset+5:decode_offset+6])[0]
    offset = decode_offset + 0x20
    x = 0
    config = b""
    enc_data = re.split(b'\x01\x00\x01\x00\x00\x00\x00', data[offset:])[0]
    for x in range(len(enc_data)):
        config += chr((key^(x%256)^enc_data[x])).encode()
    log.info("offset 0x%x", x)
    log.info("config %s", config)
    email = re.search(b"Application:PW(.*)image", config)
    ftp = re.search(b"WindowsLoad(.*)LengthWrite", config)
    web = re.search(b'80.0OK(.*)AA', config.replace(b'\\', b'AA'))
    config_dict["Email"] = email.group(1).split(b"\x00")[1].decode()
    config_dict["FTP"] = ftp.group(1).decode()
    config_dict["Web"] = web.group(1).split(b"AA")[0].decode()
    return config_dict
