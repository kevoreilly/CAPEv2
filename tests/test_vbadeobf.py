# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.integrations import vbadeobf


def test_decode_hex_returns_decoded_str_or_fallback():
    res = vbadeobf.handle_techniques(
        'x = "48656C6C6F"',
        enc_func_name="unused",
        decrypt_func=vbadeobf.decrypt_xor,
    )
    assert res == "x = Hello"

    # All-digit multi-byte hex ("http") still decodes cleanly
    http_hex = vbadeobf.handle_techniques(
        'u = "68747470"',
        enc_func_name="unused",
        decrypt_func=vbadeobf.decrypt_xor,
    )
    assert http_hex == "u = http"

    # Two-digit numeric fragments must not be misdecoded as 1-byte hex
    concat_num = vbadeobf.handle_techniques(
        'c = "rundll" & "32" & ".exe"',
        enc_func_name="unused",
        decrypt_func=vbadeobf.decrypt_xor,
    )
    assert concat_num == "c = rundll32.exe"

    # Non-printable bytes should leave original hex token intact without TypeError
    non_printable = vbadeobf.handle_techniques(
        'x = "000102FF"',
        enc_func_name="unused",
        decrypt_func=vbadeobf.decrypt_xor,
    )
    assert non_printable == "x = 000102FF"


def test_decrypt_sub_valid_and_out_of_range():
    macro = (
        "Public Function decSub(a, b)\n"
        "decSub = Chr(66 - 1)\n"
        "End Function\n"
        's = decSub("66", "1") & decSub("1", "99")\n'
    )
    func_name, enc_type = vbadeobf.find_enc_function(macro)
    assert func_name == "decSub"
    assert enc_type == "sub"

    for expr in (
        's = decSub("66", "1")',
        "s = decSub(66, 1)",
        's = decSub("1065", "1000")',
        's = decSub(Asc("B"), 1)',
    ):
        decoded = vbadeobf.handle_techniques(
            expr,
            enc_func_name=func_name,
            decrypt_func=vbadeobf.DECRYPTORS[enc_type],
        )
        assert decoded == "s = A"

    # Negative subtraction result must safely fall back without raising ValueError
    negative = vbadeobf.handle_techniques(
        's = decSub("1", "99")',
        enc_func_name=func_name,
        decrypt_func=vbadeobf.DECRYPTORS[enc_type],
    )
    assert isinstance(negative, str)


def test_handle_techniques_asc_variants_return_str():
    res = vbadeobf.handle_techniques(
        'a = Asc("A") & AscW("B") & AscB("Cdef")',
        enc_func_name="unused",
        decrypt_func=vbadeobf.decrypt_xor,
    )
    assert res == "a = 656667"
