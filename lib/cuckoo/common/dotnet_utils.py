import logging

try:
    import dnfile

    HAVE_DNFILE = True
    logging.getLogger("dnfile").setLevel(logging.CRITICAL)
    logging.getLogger("dnfile.stream").setLevel(logging.CRITICAL)
except ImportError:
    HAVE_DNFILE = False


log = logging.getLogger("dotnet_utils")


def dotnet_user_strings(file: str = False, data: bytes = False, dn_whitelisting: list = []) -> list:
    """
    Extracts user strings from a .NET file or data blob using dnfile.

    Args:
        file (str): Path to the .NET file. Default is False.
        data (bytes): Byte data of the .NET file. Default is False.
        dn_whitelisting (list): List of string patterns to whitelist. Default is an empty list.

    Returns:
        list: A list of extracted user strings that are not in the whitelist.

    Raises:
        Exception: If there is an error processing the .NET file or data.
    """

    if not HAVE_DNFILE:
        return []

    try:
        if file:
            dn = dnfile.dnPE(file)
        elif data:
            dn = dn = dnfile.dnPE(data=data)

        dn_strings = []
        if not hasattr(dn, "net") or not hasattr(dn.net, "metadata") or not hasattr(dnfile, "streams"):
            return []

        us: dnfile.stream.UserStringHeap = dn.net.metadata.streams.get(b"#US", None)
        if us:
            size = us.sizeof()
            offset = 1
            while offset < size:
                ret = us.get_with_size(offset)
                if not ret:
                    break

                buf, readlen = ret
                try:
                    if not buf.endswith(b"\x00\x00\x00"):
                        buf = buf[:-1]
                    s = dnfile.stream.UserString(buf)
                    if s.value and not any([pattern in s.value for pattern in dn_whitelisting]):
                        dn_strings.append(s.value)
                except UnicodeDecodeError:
                    log.debug("Bad string:", buf.replace(b"\x00", b""))
                # continue to next entry
                offset += readlen
    except Exception as e:
        log.error("dnFile error: ", str(e))

    dn.close()
    return dn_strings
