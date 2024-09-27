import io
import json
import logging
from contextlib import suppress

HAVE_PYCYPTODOMEX = False
with suppress(ImportError):
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter

    HAVE_PYCYPTODOMEX = True

log = logging.getLogger(__name__)


DESCRIPTION = "SparkRAT configuration parser."
AUTHOR = "t-mtsmt"


def extract_data_before_string(data, search_string, offset):
    search_bytes = search_string.encode("utf-8")

    position = data.find(search_bytes)
    if position == -1:
        return b""

    start_position = max(position - offset, 0)
    return data[start_position:position]


def decrypt_config(enc_data, key, iv):
    counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    cipher = AES.new(key, mode=AES.MODE_CTR, counter=counter)
    dec_data = cipher.decrypt(enc_data)
    config = dec_data.decode("utf-8")
    return json.loads(config)


def extract_config(data):
    if not HAVE_PYCYPTODOMEX:
        log.error("Missed pycryptodomex. Run: poetry install")
        return {}

    search_string = "DXGI_ERROR_DRIVER_INTERNAL"
    config_buf_size = 0x180
    config_buf = extract_data_before_string(data, search_string, offset=config_buf_size)

    if len(config_buf) == 0:
        log.error("Configuration is not found.")
        return {}

    if config_buf == b"\x19" * config_buf_size:
        log.debug("Configuration does not exist because the template data in the ConfigBuffer was not replaced.")
        return {}

    try:
        with io.BytesIO(config_buf) as f:
            data_len = int.from_bytes(f.read(2), "big")
            key = f.read(16)
            iv = f.read(16)
            enc_data = f.read(data_len - 32)
        return decrypt_config(enc_data, key, iv)
    except Exception as e:
        log.error("Configuration decryption failed: %s", e)
        return {}


if __name__ == "__main__":
    import sys
    from pathlib import Path

    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
