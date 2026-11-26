"""Helpers for shellcode framework modules: the stable surface a module may rely on.

Framework modules (shipped or dropped in) import this instead of reaching into shellcode_check's
internals, so the main engine can change without breaking them. See README.md.
"""

from lib.cuckoo.common.integrations import shellcode_check as _sc

#: little-endian unsigned reads that never raise: (buffer, offset) -> int (0 when out of range)
u16 = _sc._u16
u32 = _sc._u32

#: PE images in a buffer: find_embedded_pes(data, limit, max_hits) -> [{offset, nt_offset, arch, dll, ...}]
#: offsets are hex strings ('0x0'); arch is 'x86' / 'x64' (or another machine name)
find_embedded_pes = _sc.find_embedded_pes

#: raw (on-disk) size of a PE from its NT headers: pe_raw_size(data, nt_offset) -> int or 0
pe_raw_size = _sc._pe_raw_size


def extract_max():
    """Largest payload a framework may extract, in bytes (read at call time: it is configurable)."""
    return _sc.EXTRACT_MAX


def region(start, size, result, *, result_type, source, status="structural"):
    """A region of the buffer the framework accounts for, as shown in the Regions table.

    result_type: 'pe' (a PE image: shown as carried by the shellcode), 'shellcode', 'script',
    'instance' (the generator's own data block) or another short word.
    status: 'structural' (located by the layout) or 'verified' (decrypted/decoded and checked).
    """
    return {
        "start": start,
        "size": size,
        "status": status,
        "source": source,
        "result_type": result_type,
        "result": result,
        "entropy": None,
        "decoded_entropy": None,
    }


def payload(extract, offset, description):
    """A payload to extract: extract() returns the bytes (or None), called only when extraction is
    enabled, so decryption/decompression costs nothing otherwise."""
    return {"extract": extract, "offset": offset, "description": description}
