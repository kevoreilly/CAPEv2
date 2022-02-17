import string

PRINTABLE_CHARACTERS = string.ascii_letters + string.digits + string.punctuation + " \t\r\n"


def convert_char(c):
    """Escapes characters.
    @param c: dirty char.
    @return: sanitized char.
    """
    if isinstance(c, int):
        c = chr(c)
    if c in PRINTABLE_CHARACTERS:
        return c
    else:
        return f"\\x{ord(c):02x}"


def is_printable(s):
    """Test if a string is printable."""
    for c in s:
        if isinstance(c, int):
            c = chr(c)
        if c not in PRINTABLE_CHARACTERS:
            return False
    return True


def bytes2str(convert):
    """Converts bytes to string
    @param convert: string as bytes.
    @return: string.
    """
    if isinstance(convert, bytes):
        try:
            convert = convert.decode()
        except UnicodeDecodeError:
            convert = "".join(chr(_) for _ in convert)

        return convert

    if isinstance(convert, bytearray):
        try:
            convert = convert.decode()
        except UnicodeDecodeError:
            convert = "".join(chr(_) for _ in convert)

        return convert

    items = []
    if isinstance(convert, dict):
        tmp_dict = {}
        items = convert.items()
        for k, v in items:
            if isinstance(v, bytes):
                try:
                    tmp_dict[k] = v.decode()
                except UnicodeDecodeError:
                    tmp_dict[k] = "".join(str(ord(_)) for _ in v)
        return tmp_dict
    elif isinstance(convert, list):
        converted_list = []
        items = enumerate(convert)
        for k, v in items:
            if isinstance(v, bytes):
                try:
                    converted_list.append(v.decode())
                except UnicodeDecodeError:
                    converted_list.append("".join(str(ord(_)) for _ in v))

        return converted_list

    return convert


def convert_to_printable(s: str, cache=None):
    """Convert char to printable.
    @param s: string.
    @param cache: an optional cache
    @return: sanitized string.
    """
    if isinstance(s, int):
        return str(s)

    if isinstance(s, bytes):
        return bytes2str(s)

    if is_printable(s):
        return s

    if cache is None:
        return "".join(convert_char(c) for c in s)
    elif not s in cache:
        cache[s] = "".join(convert_char(c) for c in s)
    return cache[s]


def get_options(optstring):
    """Get analysis options.
    @return: options dict.
    """
    # The analysis package can be provided with some options in the following format:
    #   option1=value1,option2=value2,option3=value3
    #
    # Here we parse such options and provide a dictionary that will be made accessible to the analysis package.
    if not optstring:
        return {}

    return dict((value.strip() for value in option.split("=", 1)) for option in optstring.split(",") if option and "=" in option)
