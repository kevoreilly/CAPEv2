#!/usr/bin/env python3

__description__ = "Decode an encoded VBScript, often seen as a .vbe file"
__author__ = "John Hammond"
__date__ = "02/10/2021"

"""
Credit for this baseline code goes to Didier Stevens, from his original repo.
https://github.com/DidierStevens/DidierStevensSuite/blob/master/decode-vbe.py

All I have done is merely cleaned the code a bit, made it Python3 friendly,
and handled support for multiple #@~...#~@ markings.
https://github.com/JohnHammond/vbe-decoder/blob/master/vbe-decoder.py
"""


import re
import sys
from pathlib import Path
from typing import List


def decode_data(data: str) -> str:

    # Magic number used for the VBE voodoo magic below
    decoding_offset = 9

    # Decoding mapping for unique bytes in the encoded scheme
    decodings = (
        "\x57\x6E\x7B",
        "\x4A\x4C\x41",
        "\x0B\x0B\x0B",
        "\x0C\x0C\x0C",
        "\x4A\x4C\x41",
        "\x0E\x0E\x0E",
        "\x0F\x0F\x0F",
        "\x10\x10\x10",
        "\x11\x11\x11",
        "\x12\x12\x12",
        "\x13\x13\x13",
        "\x14\x14\x14",
        "\x15\x15\x15",
        "\x16\x16\x16",
        "\x17\x17\x17",
        "\x18\x18\x18",
        "\x19\x19\x19",
        "\x1A\x1A\x1A",
        "\x1B\x1B\x1B",
        "\x1C\x1C\x1C",
        "\x1D\x1D\x1D",
        "\x1E\x1E\x1E",
        "\x1F\x1F\x1F",
        "\x2E\x2D\x32",
        "\x47\x75\x30",
        "\x7A\x52\x21",
        "\x56\x60\x29",
        "\x42\x71\x5B",
        "\x6A\x5E\x38",
        "\x2F\x49\x33",
        "\x26\x5C\x3D",
        "\x49\x62\x58",
        "\x41\x7D\x3A",
        "\x34\x29\x35",
        "\x32\x36\x65",
        "\x5B\x20\x39",
        "\x76\x7C\x5C",
        "\x72\x7A\x56",
        "\x43\x7F\x73",
        "\x38\x6B\x66",
        "\x39\x63\x4E",
        "\x70\x33\x45",
        "\x45\x2B\x6B",
        "\x68\x68\x62",
        "\x71\x51\x59",
        "\x4F\x66\x78",
        "\x09\x76\x5E",
        "\x62\x31\x7D",
        "\x44\x64\x4A",
        "\x23\x54\x6D",
        "\x75\x43\x71",
        "\x4A\x4C\x41",
        "\x7E\x3A\x60",
        "\x4A\x4C\x41",
        "\x5E\x7E\x53",
        "\x40\x4C\x40",
        "\x77\x45\x42",
        "\x4A\x2C\x27",
        "\x61\x2A\x48",
        "\x5D\x74\x72",
        "\x22\x27\x75",
        "\x4B\x37\x31",
        "\x6F\x44\x37",
        "\x4E\x79\x4D",
        "\x3B\x59\x52",
        "\x4C\x2F\x22",
        "\x50\x6F\x54",
        "\x67\x26\x6A",
        "\x2A\x72\x47",
        "\x7D\x6A\x64",
        "\x74\x39\x2D",
        "\x54\x7B\x20",
        "\x2B\x3F\x7F",
        "\x2D\x38\x2E",
        "\x2C\x77\x4C",
        "\x30\x67\x5D",
        "\x6E\x53\x7E",
        "\x6B\x47\x6C",
        "\x66\x34\x6F",
        "\x35\x78\x79",
        "\x25\x5D\x74",
        "\x21\x30\x43",
        "\x64\x23\x26",
        "\x4D\x5A\x76",
        "\x52\x5B\x25",
        "\x63\x6C\x24",
        "\x3F\x48\x2B",
        "\x7B\x55\x28",
        "\x78\x70\x23",
        "\x29\x69\x41",
        "\x28\x2E\x34",
        "\x73\x4C\x09",
        "\x59\x21\x2A",
        "\x33\x24\x44",
        "\x7F\x4E\x3F",
        "\x6D\x50\x77",
        "\x55\x09\x3B",
        "\x53\x56\x55",
        "\x7C\x73\x69",
        "\x3A\x35\x61",
        "\x5F\x61\x63",
        "\x65\x4B\x50",
        "\x46\x58\x67",
        "\x58\x3B\x51",
        "\x31\x57\x49",
        "\x69\x22\x4F",
        "\x6C\x6D\x46",
        "\x5A\x4D\x68",
        "\x48\x25\x7C",
        "\x27\x28\x36",
        "\x5C\x46\x70",
        "\x3D\x4A\x6E",
        "\x24\x32\x7A",
        "\x79\x41\x2F",
        "\x37\x3D\x5F",
        "\x60\x5F\x4B",
        "\x51\x4F\x5A",
        "\x20\x42\x2C",
        "\x36\x65\x57",
    )

    # The combination switching for the encoded bytes
    combinations = (
        0,
        1,
        2,
        0,
        1,
        2,
        1,
        2,
        2,
        1,
        2,
        1,
        0,
        2,
        1,
        2,
        0,
        2,
        1,
        2,
        0,
        0,
        1,
        2,
        2,
        1,
        0,
        2,
        1,
        2,
        2,
        1,
        0,
        0,
        2,
        1,
        2,
        1,
        2,
        0,
        2,
        0,
        0,
        1,
        2,
        0,
        2,
        1,
        0,
        2,
        1,
        2,
        0,
        0,
        1,
        2,
        2,
        0,
        0,
        1,
        2,
        0,
        2,
        1,
    )

    # Replace the data with some strings we already know the meaning of
    replacements = {"@&": chr(10), "@#": chr(13), "@*": ">", "@!": "<", "@$": "@"}
    for to_replace, replace_with in replacements.items():
        data = data.replace(to_replace, replace_with)

    # Now that it is prepared, replace all the other encoded data
    result = ""
    index = -1
    bad_bytes = {60, 62, 64}
    for char in data:
        byte = ord(char)
        if byte < 128:
            index += 1
        if byte == decoding_offset or 31 < byte < 128 and byte not in bad_bytes:
            # Do the translation to get the right byte
            char = decodings[byte - decoding_offset][combinations[index % 64]]

        result += char

    return result


def fatal_error(message: str):
    """
    Convenience function to display an error message and quit.
    """
    sys.stderr.write(f"[!] fatal error, {message}\n")
    sys.exit(-1)


def success(message: str):
    """
    Convenience function to display a success message and quit.
    """
    sys.stderr.write(f"[+] success, {message}\n")


def validate_files(files: List[str]):
    """
    Check if the supplied files actually exist and are in fact files
    """
    for file in files:
        p = Path(file)
        if not p.exists() or not p.is_file():
            fatal_error(f"supplied file '{file}' does not exist")


def decode_files(files: List[str]) -> str:
    return "\n".join(decode_file(file) for file in files)


def decode_file(file: str, contents: bytes = False) -> str:
    if not contents:
        try:
            contents = Path(file).read_bytes().decode("latin-1", errors="ignore")
        except Exception as e:
            fatal_error(f"{e.message}")

    else:
        if isinstance(contents, bytes):
            contents = contents.decode("latin-1", errors="ignore")

    encoded_data = re.findall(r"#@~\^......==(.+)......==\^#~@", contents)
    return "\n".join(decode_data(data) for data in encoded_data)


def main(files: List[str], output_file: str):
    """
    Decode an encoded VBScript, often seen as a .vbe file
    """

    # Ensure we can work with these files, and then decode them
    validate_files(files)
    output = decode_files(files)

    # Return the results as requested.
    if not output_file:
        sys.stdout.write(output)
    else:
        try:
            _ = Path(output_file).write_text(output)
            success(f"wrote decoded vbscript to '{output_file}'")
        except Exception as e:
            fatal_error(f"{e.message}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument("files", metavar="file", type=str, nargs="+", help="file to decode")
    parser.add_argument("-o", "--output", metavar="output", type=str, default=None, help="output file (default stdout)")
    args = parser.parse_args()

    main(args.files, args.output)
