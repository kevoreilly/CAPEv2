import contextlib
import logging
import os
from argparse import ArgumentParser, Namespace
from binascii import hexlify
from hashlib import md5
from typing import Dict

from Crypto.Cipher import ARC4

from .constants import functions, macros, operators


def parse_args() -> Namespace:
    usage = "detokenize.py [OPTION]... [FILES]..."
    arg_parser = ArgumentParser(description=usage)
    arg_parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Increase verbosity. Can specify multiple times for more verbose output"
    )
    arg_parser.add_argument("-d", "--dump", dest="dump_dir", action="store", default=None, help="Dump path for output scripts")
    arg_parser.add_argument(
        "-p", "--print", dest="print", action="store_true", default=False, help="Write detokenized scripts to stdout"
    )
    arg_parser.add_argument("files", nargs="+")
    return arg_parser.parse_args()


def configure_logger(log_level: int):
    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(log_level, 0), 3)  # clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level], format="%(asctime)s - %(name)s - %(levelname)-8s %(message)s")


def CryptDeriveKey(passphrase) -> bytes:
    """
    Stupid MS-specific method of deriving session key from passphrase
    https://stackoverflow.com/questions/18093316/ms-cryptoapi-giving-wrong-rc4-results
    """
    return md5(passphrase).digest()[:5] + b"\x00" * 11


class Kixtart:
    def __init__(self, path, dump_dir=None):
        self.logger = logging.getLogger("Kixtart-Detokenizer")
        self.path = path
        self.dump_dir = dump_dir or "."
        with open(path, "rb") as fp:
            self.data = bytearray(fp.read())
        self.header = self.data[:6]

        # TODO: one of these bytes should actually indicate if it is encrypted or not
        if self.header != b"\x1a\xaf\x06\x00\x00\x10":
            raise ValueError(f"Unrecognized header {hexlify(self.header)}")
        self.key = self.data[0x06:0x16]
        self.session_key = CryptDeriveKey(self.key)
        self.ciphertext = self.data[0x16:]

    def decrypt(self) -> bytes:
        arc4 = ARC4.new(key=self.session_key)
        self.logger.info("[*]\tdecrypting with session key %s", hexlify(self.session_key).decode())
        token_data = arc4.decrypt(bytes(self.ciphertext))
        self.code_length = int.from_bytes(token_data[:4], byteorder="little")
        self.tokenized = token_data[4:]
        self.logger.debug("raw tokenized script: %s", hexlify(self.tokenized).decode())
        self.parse()
        return self.tokenized

    def parse_labels(self, data: bytes) -> Dict[int, str]:
        labels = {}
        string = ""
        i = 0
        while i < len(data):
            if data[i] == 0:
                idx = int.from_bytes(data[i + 1 : i + 5], byteorder="little")
                labels[idx] = string
                string = ""
                i += 5
            else:
                string += chr(data[i])
                i += 1
        return labels

    def parse_functions(self):
        i = 0
        buf = self.function_data
        self.logger.debug("Parsing function data %s", hexlify(buf).decode())
        # TODO have not looked into parsing scripts relying on multiple files
        filename = ""
        while buf[i] != 0:
            filename += chr(buf[i])
            i += 1
        i += 1  # eat null terminator for filename
        while i < len(buf):
            start = i
            try:
                function_name = ""
                while buf[i] != 0:
                    function_name += chr(buf[i])
                    i += 1
                i += 5  # Seems to always be d9 ff ff ff
                parameters = []
                if buf[i] == 0:
                    i += 1
                else:
                    parameter_types = ""
                    while buf[i] != 0:
                        parameter_types += chr(buf[i])
                        i += 1
                    i += 1
                    for _ in parameter_types:
                        param = ""
                        while buf[i] != 0:
                            param += chr(buf[i])
                            i += 1
                        i += 1
                        parameters.append(f"${param}")
                function_length = int.from_bytes(buf[i : i + 4], byteorder="little")
                i += 4
                function_data = buf[i : i + function_length]
                i += function_length
                label_length = int.from_bytes(buf[i : i + 4], byteorder="little")
                self.logger.debug("label length: %d", label_length)
                labels = {}
                i += 4  # label length
                if label_length:
                    label_data = buf[i : i + label_length]
                    labels = self.parse_labels(label_data)
                    self.logger.debug("Label data: %s", hexlify(label_data))
                    self.logger.debug("Labels: %s", labels)
                    i += label_length

                # func = f"{filename}.{function_name}({','.join(parameters)})"
                func = f"{function_name}({','.join(parameters)})"
                # self.logger.debug("%s: %s", func, hexlify(function_data).decode())
                self.detokenize(function_data, labels, func)
                i += 1
            except Exception:
                self.logger.error("Failed to parse remaining function data %s", hexlify(buf[start:]))
                return

    def dump(self):
        script_name = f"{os.path.splitext(os.path.basename(self.path))[0]}.kix"
        path = os.path.join(self.dump_dir, script_name)
        self.logger.info("Writing detokenized version of %s to, %s", self.path, path)
        with open(path, "w") as fp:
            fp.write(os.linesep.join(self.script))

    def trim_script(self):
        # trim beginning and ending lines from script
        last = 0
        first = 0
        for i, char in enumerate(self.script):
            if char:
                if first == 0:
                    first = i
                last = i
        self.script = self.script[first : last + 1]

        # remove excessive whitespace (likely, where comments used to be)
        filtered = [self.script[0]]
        for i in range(1, len(self.script)):
            if self.script[i] != "" or self.script[i - 1] != "":
                filtered.append(self.script[i])
        self.script = filtered

    def parse(self):
        self.script = [""] * 9999

        labels_offset = self.code_length
        labels_length = int.from_bytes(self.tokenized[labels_offset : labels_offset + 4], byteorder="little")
        self.logger.debug("label length: %02X", labels_length)
        raw_label_data = self.tokenized[labels_offset + 4 : labels_offset + labels_length]
        self.logger.debug(hexlify(raw_label_data))
        labels = self.parse_labels(raw_label_data)

        self.logger.debug("Raw label data: %s", raw_label_data)
        self.logger.info("Labels: %s", labels)
        vars_offset = labels_offset + labels_length + 4
        vars_length = int.from_bytes(self.tokenized[vars_offset : vars_offset + 4], byteorder="little")
        self.variables = self.tokenized[vars_offset + 4 : vars_offset + 4 + vars_length].split(b"\x00")
        self.logger.info("Variables: ")
        for i, variable in enumerate(self.variables):
            self.logger.info("\t%02X: %s", i, variable)

        functions_offset = vars_offset + vars_length
        functions_length = int.from_bytes(self.tokenized[functions_offset : functions_offset + 4], byteorder="little")
        self.function_data = self.tokenized[functions_offset + 4 : functions_offset + functions_length]

        self.detokenize(self.tokenized, labels=labels, function=None)

        if self.function_data:
            # self.logger.debug("Function data: %s", hexlify(self.function_data).decode())
            self.parse_functions()
        self.trim_script()

    def detokenize(self, buf, labels=None, function=None):
        self.logger.debug("Detokenize %s: %s, labels=%s, function=%s", function, hexlify(buf), labels, function)
        i = 0
        line_num = 0
        first_line = 9999
        last_line = 0
        while True:
            b = buf[i]
            try:
                n = buf[i + 1]
            except Exception:
                n = 0
            # parse line number
            if b in [0xEC, 0xED]:
                # 0xEC - 1 byte line num, 0xED - 2 byte line num
                offset_size = b - 0xEB
                line_num = int.from_bytes(buf[i + 1 : i + 1 + offset_size], byteorder="little")
                # record first and last lines, so that if this is a function, we can wrap it in function XYZ and endfunction
                first_line = min(line_num, first_line)
                last_line = max(line_num, last_line)
                # No label for some lines
                with contextlib.suppress(KeyError):
                    self.script[line_num] += f":{labels[i]}\n"
                i += 1 + offset_size
                continue

            # 1 byte int
            if b == 0xDA:
                self.script[line_num] += str(n)
                i += 2
                continue
            # 2 byte int
            elif b == 0xDB:
                self.script[line_num] += str(int.from_bytes(buf[i + 1 : i + 3], byteorder="little"))
                i += 3
                continue
            # I have no idea what this is
            elif b == 0xDC:
                self.logger.warning("Unknown command 0xDC. Skipping 5 bytes")
                i += 5
                continue
            # String literal - inline
            elif b == 0xDE:
                i += 1
                name = ""
                while buf[i] != 0:
                    name += chr(buf[i])
                    i += 1
                self.script[line_num] += f'"{name}"'
                i += 1
                continue
            # Variable name - inline
            elif b == 0xDF:
                i += 1
                name = "$"
                while buf[i] != 0:
                    name += chr(buf[i])
                    i += 1
                self.script[line_num] += name
                i += 1
                continue
            # Macro
            elif b == 0xE0:
                if n in macros:
                    self.script[line_num] += f"@{macros[n]}"
                else:
                    self.logger.warning("unrecognized macro 0x%02X, using <UNKNOWN_MACRO>", n)
                    self.script[line_num] += "@<UNKNOWN_MACRO>"
                i += 2
                continue
            # Variable name from vars table
            elif b == 0xE7:
                # TODO is this null terminated or 2 bytes?
                offset = int.from_bytes(buf[i + 1 : i + 3], byteorder="little")
                self.script[line_num] += f"${self.variables[offset].decode()}"
                i += 3
                continue
            # object method -  Fetch method name from vars table
            elif b == 0xE8:
                # TODO is this null terminated or 2 bytes?
                offset = int.from_bytes(buf[i + 1 : i + 3], byteorder="little")
                self.script[line_num] += f".{self.variables[offset].decode()}"
                i += 3
                continue
            # Function? name from var table
            elif b == 0xE9:
                # TODO is this null terminated or 2 bytes?
                offset = int.from_bytes(buf[i + 1 : i + 3], byteorder="little")
                self.script[line_num] += self.variables[offset].decode()
                i += 3
                continue
            # Keyword
            elif b == 0xEA:
                if n in functions:
                    self.script[line_num] += functions[n]
                else:
                    self.logger.warning("Unrecognized function 0x%02X, using <UNKNOWN_KEYWORD>", n)
                    self.script[line_num] += "<UNKNOWN_KEYWORD>"
                i += 2
                continue
            # Single char literal + null
            elif b == 0xEF:
                self.script[line_num] += chr(n)
                i += 3
                continue
            # check operators/symbols
            elif b in operators:
                self.script[line_num] += f"{operators[b]}"
                i += 1
                continue
            # End Script
            elif b == 0xF1:
                if function:
                    if not self.script[first_line - 1]:
                        self.script[first_line - 1] = f"Function {function}"
                    if not self.script[last_line + 1]:
                        self.script[last_line + 1] = "EndFunction"
                return

            self.logger.critical("Failed to parse token %02X in %s", b, hexlify(buf[i - 2 : i + 3]))
            return


def main():
    options = parse_args()
    if options.dump_dir and not os.path.exists(options.dump_dir):
        os.makedirs(options.dump_dir)
    configure_logger(options.verbose)

    for arg in options.files:
        kix = Kixtart(arg)
        kix.decrypt()
        kix.dump()
        if options.print:
            print()
            print(f"[{arg}]")
            print(os.linesep.join(kix.script))


if __name__ == "__main__":
    main()
