#!/usr/bin/env python3
#
# dotnetpe_payload.py
#
# Author: jeFF0Falltrades
#
# Provides a wrapper class for accessing metadata from a DotNetPE object and
# performing RVA to data offset conversions
#
# MIT License
#
# Copyright (c) 2024 Jeff Archer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from hashlib import sha256
from logging import getLogger

from dnfile import dnPE

from .config_parser_exception import ConfigParserException
from .dotnet_constants import MDT_FIELD_DEF, MDT_METHOD_DEF, MDT_STRING

logger = getLogger(__name__)


class DotNetPEPayload:
    def __init__(self, file_data, yara_rule=None):
        # self.file_path = file_path
        self.data = file_data  # self.get_file_data()
        self.sha256 = self.calculate_sha256()
        self.dotnetpe = None
        try:
            self.dotnetpe = dnPE(data=file_data, clr_lazy_load=True)
        except Exception as e:
            logger.exception(e)
        self.yara_match = ""
        if yara_rule is not None:
            self.yara_match = self.match_yara(yara_rule)

    # Given a byte array's size and RVA, translates the RVA to the offset of
    # the byte array and returns the bytes of the array as a byte string
    def byte_array_from_size_and_rva(self, arr_size, arr_rva):
        arr_field_rva = self.fieldrva_from_rva(arr_rva)
        arr_offset = self.offset_from_rva(arr_field_rva)
        arr_value = self.data[arr_offset : arr_offset + arr_size]
        return arr_value

    # Calculates the SHA256 hash of file data
    def calculate_sha256(self):
        sha256_hash = sha256()
        sha256_hash.update(self.data)
        return sha256_hash.hexdigest()

    # Given an RVA, derives the corresponding Field name from the RVA
    def field_name_from_rva(self, rva):
        return self.dotnetpe.net.mdtables.Field.rows[(rva ^ MDT_FIELD_DEF) - 1].Name.value

    # Given an RVA, derives the corresponding FieldRVA value from the RVA
    def fieldrva_from_rva(self, rva):
        field_id = rva ^ MDT_FIELD_DEF
        for row in self.dotnetpe.net.mdtables.FieldRva:
            if row.struct.Field_Index == field_id:
                return row.struct.Rva
        raise ConfigParserException(f"Could not find FieldRVA for address {rva}")

    # Reads in payload binary content
    def get_file_data(self):
        logger.debug(f"Reading contents from: {self.file_path}")
        try:
            with open(self.file_path, "rb") as fp:
                data = fp.read()
        except Exception as e:
            raise ConfigParserException(f"Error reading from path: {self.file_path}") from e
        logger.debug("Successfully read data")
        return data

    # Tests a given YARA rule object against the file at file_path
    def match_yara(self, rule):
        try:
            match = rule.match(data=self.file_data)
            return str(match[0]) if len(match) > 0 else "No match"
        except Exception as e:
            logger.exception(e)
            return f"Exception encountered: {e}"

    # Given a method name, returns RVAs of methods matching that name
    def method_rvas_from_name(self, name):
        return [row.Rva for row in self.dotnetpe.net.mdtables.MethodDef if row.Name.value == name]

    # Given the offset to an instruction, reverses the instruction to its
    # parent Method, and then finds the subsequent Method in the MethodDef
    # table and returns its offset or index
    def next_method_from_instruction_offset(self, ins_offset, step_back=0, by_token=False):
        # Translate the instruction offset to RVA
        ins_rva = self.dotnetpe.get_rva_from_offset(ins_offset)
        # Get both the regular MethodDef table and a sorted (by RVA) copy
        # This is because the table is not guaranteed to be ordered by RVA
        methods = self.dotnetpe.net.mdtables.MethodDef.rows
        sorted_methods = sorted(methods, key=lambda m: m.Rva)
        # Go through the sorted table and find the Method RVA that is greater
        # than the instruction RVA (the subsequent function), and use step_back
        # to get the function containing the instruction if necessary
        for idx, method in enumerate(sorted_methods):
            if method.Rva > ins_rva:
                return (
                    # Add 1 to token ID as table starts at index 1, not 0
                    methods.index(sorted_methods[idx - step_back]) + 1 + MDT_METHOD_DEF
                    if by_token
                    else self.offset_from_rva(methods[methods.index(sorted_methods[idx - step_back])].Rva)
                )
        raise ConfigParserException(f"Could not find method from instruction offset {ins_offset}")

    # Given an RVA, returns a data/file offset
    def offset_from_rva(self, rva):
        return self.dotnetpe.get_offset_from_rva(rva)

    # Given a string offset, and, optionally, a delimiter, extracts the string
    def string_from_offset(self, str_offset, delimiter=b"\0"):
        try:
            result = self.data[str_offset:].partition(delimiter)[0]
        except Exception as e:
            raise ConfigParserException(
                f"Could not extract string value from offset {hex(str_offset)} with delimiter {delimiter}"
            ) from e
        return result

    def string_from_range(self, start_offset, end_offset):
        try:
            return self.data[start_offset, end_offset]
        except Exception as e:
            raise ConfigParserException(f"Could not extract string value from range {hex(start_offset)}:{hex(end_offset)}") from e

    # Given an RVA, derives the corresponding User String
    def user_string_from_rva(self, rva):
        return self.dotnetpe.net.user_strings.get(rva ^ MDT_STRING).value
