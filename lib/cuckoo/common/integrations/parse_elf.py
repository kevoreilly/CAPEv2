# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from typing import Any, Dict, List

from lib.cuckoo.common.utils import convert_to_printable

try:
    from elftools.common.exceptions import ELFError
    from elftools.elf.constants import E_FLAGS
    from elftools.elf.descriptions import (
        describe_dyn_tag,
        describe_e_machine,
        describe_e_type,
        describe_e_version_numeric,
        describe_ei_class,
        describe_ei_data,
        describe_ei_osabi,
        describe_ei_version,
        describe_note,
        describe_p_flags,
        describe_p_type,
        describe_reloc_type,
        describe_sh_type,
        describe_symbol_bind,
        describe_symbol_type,
    )
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile
    from elftools.elf.enums import ENUM_D_TAG
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.segments import NoteSegment
except ImportError:
    ELFFile = False


class ELF:
    def __init__(self, file_path):
        self.file_path = file_path
        self.elf = None
        self.result = {}

    def run(self) -> Dict[str, Any]:
        try:
            with open(self.file_path, "rb") as f:
                self.elf = ELFFile(f)
            self.result["file_header"] = self._get_file_header()
            self.result["section_headers"] = self._get_section_headers()
            self.result["program_headers"] = self._get_program_headers()
            self.result["dynamic_tags"] = self._get_dynamic_tags()
            self.result["symbol_tables"] = self._get_symbol_tables()
            self.result["relocations"] = self._get_relocations()
            self.result["notes"] = self._get_notes()
            # TODO: add library name per import (see #807)
        except ELFError as e:
            if e.message != "Magic number does not match":
                raise

        return self.result

    def _get_file_header(self) -> Dict[str, str]:
        return {
            # TODO
            "magic": convert_to_printable(self.elf.e_ident_raw[:4]),
            "class": describe_ei_class(self.elf.header.e_ident["EI_CLASS"]),
            "data": describe_ei_data(self.elf.header.e_ident["EI_DATA"]),
            "ei_version": describe_ei_version(self.elf.header.e_ident["EI_VERSION"]),
            "os_abi": describe_ei_osabi(self.elf.header.e_ident["EI_OSABI"]),
            "abi_version": self.elf.header.e_ident["EI_ABIVERSION"],
            "type": describe_e_type(self.elf.header["e_type"]),
            "machine": describe_e_machine(self.elf.header["e_machine"]),
            "version": describe_e_version_numeric(self.elf.header["e_version"]),
            "entry_point_address": self._print_addr(self.elf.header["e_entry"]),
            "start_of_program_headers": self.elf.header["e_phoff"],
            "start_of_section_headers": self.elf.header["e_shoff"],
            "flags": f"{self._print_addr(self.elf.header['e_flags'])}{self._decode_flags(self.elf.header['e_flags'])}",
            "size_of_this_header": self.elf.header["e_ehsize"],
            "size_of_program_headers": self.elf.header["e_phentsize"],
            "number_of_program_headers": self.elf.header["e_phnum"],
            "size_of_section_headers": self.elf.header["e_shentsize"],
            "number_of_section_headers": self.elf.header["e_shnum"],
            "section_header_string_table_index": self.elf.header["e_shstrndx"],
        }

    def _get_section_headers(self) -> List[Dict[str, str]]:
        return [
            {
                "name": section.name,
                "type": describe_sh_type(section["sh_type"]),
                "addr": self._print_addr(section["sh_addr"]),
                "size": section["sh_size"],
            }
            for section in self.elf.iter_sections()
        ]

    def _get_program_headers(self) -> List[Dict[str, str]]:
        return [
            {
                "type": describe_p_type(segment["p_type"]),
                "addr": self._print_addr(segment["p_vaddr"]),
                "flags": describe_p_flags(segment["p_flags"]).strip(),
                "size": segment["p_memsz"],
            }
            for segment in self.elf.iter_segments()
        ]

    def _get_dynamic_tags(self) -> List[Dict[str, str]]:
        dynamic_tags = []
        for section in self.elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            dynamic_tags.extend(
                {
                    "tag": self._print_addr(ENUM_D_TAG.get(tag.entry.d_tag, tag.entry.d_tag)),
                    "type": str(tag.entry.d_tag)[3:],
                    "value": self._parse_tag(tag),
                }
                for tag in section.iter_tags()
            )

        return dynamic_tags

    def _get_symbol_tables(self) -> List[Dict[str, str]]:
        symbol_tables = []
        for section in self.elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            symbol_tables.extend(
                {
                    "value": self._print_addr(symbol["st_value"]),
                    "type": describe_symbol_type(symbol["st_info"]["type"]),
                    "bind": describe_symbol_bind(symbol["st_info"]["bind"]),
                    "ndx_name": symbol.name,
                }
                for symbol in section.iter_symbols()
            )

        return symbol_tables

    def _get_relocations(self) -> List[Dict[str, str]]:
        relocations = []
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            section_relocations = set()
            for rel in section.iter_relocations():
                relocation = {
                    "offset": self._print_addr(rel["r_offset"]),
                    "info": self._print_addr(rel["r_info"]),
                    "type": describe_reloc_type(rel["r_info_type"], self.elf),
                    "value": "",
                    "name": "",
                }

                if rel["r_info_sym"] != 0:
                    symtable = self.elf.get_section(section["sh_link"])
                    symbol = symtable.get_symbol(rel["r_info_sym"])
                    # Some symbols have zero "st_name", so instead use
                    # the name of the section they point at
                    if symbol["st_name"] == 0:
                        symsec = self.elf.get_section(symbol["st_shndx"])
                        symbol_name = symsec.name
                    else:
                        symbol_name = symbol.name

                    relocation["value"] = self._print_addr(symbol["st_value"])
                    relocation["name"] = symbol_name

                section_relocations.add(relocation)

            relocations.append(
                {
                    "name": section.name,
                    "entries": section_relocations,
                }
            )
        return relocations

    def _get_notes(self) -> List[Dict[str, str]]:
        notes = []
        for segment in self.elf.iter_segments():
            if not isinstance(segment, NoteSegment):
                continue
            notes.extend(
                {
                    "owner": note["n_name"],
                    "size": self._print_addr(note["n_descsz"]),
                    "note": describe_note(note),
                    "name": note["n_name"],
                }
                for note in segment.iter_notes()
            )

        return notes

    def _print_addr(self, addr: int) -> str:
        return f"0x{addr:08x}" if self.elf.elfclass == 32 else f"0x{addr:016x}"

    def _decode_flags(self, flags) -> str:
        description = ""
        if self.elf["e_machine"] == "EM_ARM":
            if flags & E_FLAGS.EF_ARM_HASENTRY:
                description = ", has entry point"

            version = flags & E_FLAGS.EF_ARM_EABIMASK
            if version == E_FLAGS.EF_ARM_EABI_VER5:
                description = ", Version5 EABI"
        elif self.elf["e_machine"] == "EM_MIPS":
            if flags & E_FLAGS.EF_MIPS_NOREORDER:
                description = ", noreorder"
            if flags & E_FLAGS.EF_MIPS_CPIC:
                description = ", cpic"
            if not (flags & E_FLAGS.EF_MIPS_ABI2) and not (flags & E_FLAGS.EF_MIPS_ABI_ON32):
                description = ", o32"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_1:
                description = ", mips1"

        return description

    def _parse_tag(self, tag) -> str:
        if tag.entry.d_tag == "DT_NEEDED":
            return f"Shared library: [{tag.needed}]"
        elif tag.entry.d_tag == "DT_RPATH":
            return f"Library rpath: [{tag.rpath}]"
        elif tag.entry.d_tag == "DT_RUNPATH":
            return f"Library runpath: [{tag.runpath}]"
        elif tag.entry.d_tag == "DT_SONAME":
            return f"Library soname: [{tag.soname}]"
        elif isinstance(tag.entry.d_tag, str) and tag.entry.d_tag.endswith(("SZ", "ENT")):
            return f"{tag['d_val']} (bytes)"
        elif isinstance(tag.entry.d_tag, str) and tag.entry.d_tag.endswith(("NUM", "COUNT")):
            return str(tag["d_val"])
        elif tag.entry.d_tag == "DT_PLTREL":
            return describe_dyn_tag(tag.entry.d_val).lstrip("DT_")
        return self._print_addr(tag["d_val"])
