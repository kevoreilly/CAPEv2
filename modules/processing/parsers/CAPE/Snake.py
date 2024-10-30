import base64
import hashlib
import logging
import re
import traceback

import dnfile

try:
    from Cryptodome.Cipher import DES
    from Cryptodome.Util.Padding import unpad
except ModuleNotFoundError:
    raise ModuleNotFoundError("Please run: pip3 install pycryptodomex")

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


def is_base64(s):
    pattern = re.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$")
    if not s or len(s) < 1:
        return False
    else:
        return pattern.match(s)


def pad(text):
    n = len(text) % 8
    return text + (b" " * n)


def md5(string: bytes) -> bytes:
    return bytes.fromhex(hashlib.md5(string).hexdigest())


def handle_plain(dotnet_file, c2_type, user_strings):
    user_strings_list = list(user_strings.values())
    if c2_type == "Telegram":
        token = dotnet_file.net.user_strings.get(user_strings_list[15]).value.__str__()
        chat_id = dotnet_file.net.user_strings.get(user_strings_list[16]).value.__str__()
        return {"Type": "Telegram", "C2": f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}"}
    elif c2_type == "SMTP":
        smtp_from = dotnet_file.net.user_strings.get(user_strings_list[7]).value.__str__()
        smtp_password = dotnet_file.net.user_strings.get(user_strings_list[8]).value.__str__()
        smtp_host = dotnet_file.net.user_strings.get(user_strings_list[9]).value.__str__()
        smtp_to = dotnet_file.net.user_strings.get(user_strings_list[10]).value.__str__()
        smtp_port = dotnet_file.net.user_strings.get(user_strings_list[11]).value.__str__()
        return {
            "Type": "SMTP",
            "Host": smtp_host,
            "Port": smtp_port,
            "From Address": smtp_from,
            "To Address": smtp_to,
            "Password": smtp_password,
        }
    elif c2_type == "FTP":
        ftp_username = dotnet_file.net.user_strings.get(user_strings_list[12]).value.__str__()
        ftp_password = dotnet_file.net.user_strings.get(user_strings_list[13]).value.__str__()
        ftp_host = dotnet_file.net.user_strings.get(user_strings_list[14]).value.__str__()
        return {"Type": "FTP", "Host": ftp_host, "Username": ftp_username, "Password": ftp_password}


def handle_encrypted(dotnet_file, data, c2_type, user_strings):
    # Match decrypt string pattern
    decrypt_string_pattern = re.compile(
        Rb"""(?x)
    \x72(...)\x70
    \x7E(...)\x04
    \x28...\x06
    \x80...\x04
    """
    )

    config_dict = None
    decrypted_strings = []

    matches2 = decrypt_string_pattern.findall(data)
    for match in matches2:
        string_index = int.from_bytes(match[0], "little")
        user_string = dotnet_file.net.user_strings.get(string_index).value
        # Skip user strings that are empty/not base64
        if user_string == "Yx74dJ0TP3M=" or not is_base64(user_string):
            continue
        field_row_index = int.from_bytes(match[1], "little")
        field_name = dotnet_file.net.mdtables.Field.get_with_row_index(field_row_index).Name.__str__()
        key_index = user_strings[field_name]
        key_str = dotnet_file.net.user_strings.get(key_index).value.__str__()
        key = md5(key_str.encode())[:8]
        des = DES.new(key, DES.MODE_ECB)

        decoded_str = base64.b64decode(user_string)
        padded_str = pad(decoded_str)
        decrypted_text = des.decrypt(padded_str)
        plaintext_bytes = unpad(decrypted_text, DES.block_size)
        plaintext = plaintext_bytes.decode()
        decrypted_strings.append(plaintext)

    if decrypted_strings:
        if c2_type == "Telegram":
            token, chat_id = decrypted_strings
            config_dict = {"Type": "Telegram", "C2": f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}"}
        elif c2_type == "SMTP":
            smtp_from, smtp_password, smtp_host, smtp_to, smtp_port = decrypted_strings
            config_dict = {
                "Type": "SMTP",
                "Host": smtp_host,
                "Port": smtp_port,
                "From Address": smtp_from,
                "To Address": smtp_to,
                "Password": smtp_password,
            }
        elif c2_type == "FTP":
            ftp_username, ftp_password, ftp_host = decrypted_strings
            config_dict = {"Type": "FTP", "Host": ftp_host, "Username": ftp_username, "Password": ftp_password}
    return config_dict


def extract_config(data):

    try:
        dotnet_file = dnfile.dnPE(data=data)
    except Exception as e:
        log.debug(f"Exception when attempting to parse .NET file: {e}")
        log.debug(traceback.format_exc())

    # ldstr, stsfld
    static_strings = re.compile(
        Rb"""(?x)
    \x72(...)\x70
    \x80(...)\x04
    """
    )

    # Get user strings and C2 type
    user_strings = {}
    c2_type = None
    matches = static_strings.findall(data)
    for match in matches:
        try:
            string_index = int.from_bytes(match[0], "little")
            string_value = dotnet_file.net.user_strings.get(string_index).value.__str__()
            field_index = int.from_bytes(match[1], "little")
            field_name = dotnet_file.net.mdtables.Field.get_with_row_index(field_index).Name.__str__()
            if string_value == "$%TelegramDv$":
                c2_type = "Telegram"

            elif string_value == "$%SMTPDV$":
                c2_type = "SMTP"

            elif string_value == "%FTPDV$":
                c2_type = "FTP"
            else:
                user_strings[field_name] = string_index
        except Exception as e:
            log.debug(f"There was an exception parsing user strings: {e}")
            log.debug(traceback.format_exc())

    if c2_type is None:
        raise ValueError("Could not identify C2 type.")

    # Handle encrypted strings
    config_dict = handle_encrypted(dotnet_file, data, c2_type, user_strings)
    if config_dict is None:
        # Handle plain strings
        config_dict = handle_plain(dotnet_file, c2_type, user_strings)

    return config_dict


if __name__ == "__main__":
    import sys

    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
