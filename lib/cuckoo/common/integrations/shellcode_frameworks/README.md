# Shellcode framework identifiers and extractors

The static shellcode check (`lib/cuckoo/common/integrations/shellcode_check.py`) recognises the
output of known shellcode generators (Donut, sRDI, pe2shc, ...) and can extract what they carry. Each
generator is one Python module.

Every `.py` file in this folder (`lib/cuckoo/common/integrations/shellcode_frameworks/`) is a framework
module. That includes the ones shipped with CAPE (`donut.py`, `srdi.py`, `pe2shc.py`) and any you add,
such as a loader you track. `api.py` holds the helpers modules use, and files starting with `_` are
not loaded.

To add a framework, drop a `.py` file in this folder and restart the CAPE processor and web services.
Modules are loaded once per process, on first use. A module is skipped, with an error in the log, if:

- it fails to import
- it has no `NAME` or `identify()`
- it reuses a `NAME` already loaded (files load in name order)

As with custom signatures, you keep your own modules: back them up and restore them across CAPE
updates.

## What a module does (and does not do)

A framework module **proves a layout from the raw bytes** and, optionally, **extracts the payload**.
It does not disassemble code or score behaviour. The main engine does that for every buffer
(PEB walks, API hashing, decoders, stack strings, syscalls...), whatever generator made it.

The module only reads bytes. No disassembly or emulation is needed, so it is fast, and its answer is
exact. When a module returns `confidence: "identified"`, the engine:

- sets the verdict to `shellcode` and adds the `framework_layout` indicator (STRONG)
- uses the module's `arch` to choose the disassembly mode when no architecture was given
- adds the module's regions to the Regions table, with the framework badge
- records a CAPE detection for `FAMILY` (when shellcode detections are enabled)
- extracts the payload, when payload extraction is enabled

**Framework attribution must be exact.** Return `"identified"` only when the layout is proven, meaning
a fixed structure plus at least one internal consistency check, such as:

- a length or offset field that lands exactly where the next part starts
- a computed offset that lands on a PE of the expected architecture
- a known plaintext after decrypting with the key stored in the blob

Code that other tools copy (a public API resolver, a common decoder stub) is not a framework.
Leave it to the indicators. Return `"possible"` for anything weaker. A possible match is
listed for the analyst, but it never changes the verdict or score, and it never creates a detection.

## The contract

```python
NAME = "MyLoader"       # required: unique, shown in the report
FAMILY = "MyFamily"     # optional: CAPE detection family when identified (default: NAME)
PRIORITY = 100          # optional: lower runs first (shipped: Donut 10, sRDI 20, pe2shc 30; default 100)


def identify(data: bytes) -> dict | None:
    ...
```

`identify()` receives the whole buffer and returns `None`, or a dict:

| Key | Required | Meaning |
|---|---|---|
| `confidence` | yes | `"identified"` (exact proof) or `"possible"` |
| `arch` | no | `"x86"`, `"x64"`, `"x86+x64"` or `None` |
| `evidence` | no | list of short sentences: what was matched and checked |
| `details` | no | dict shown in the Frameworks table. `payload` (e.g. `"x64 DLL"`) is also used for the badge |
| `regions` | no | list of `api.region(...)` dicts: the parts of the buffer the layout accounts for |
| `iocs` | no | dict like the engine's IOCs, e.g. `{"urls": [...]}` for a staging URL |
| `_payload` | no | `api.payload(extract, offset, description)`: what to extract (identified only) |

The loader fills `name` from `NAME`, and fills any optional key you leave out.

Modules run in `PRIORITY` order, and **the first `"identified"` result wins**, because one generator
writes the outer layout. With the default priority (100) a module runs after the shipped ones. Give a module a lower
`PRIORITY` only when its layout wraps another generator's output and should be reported instead of it.

If a module raises, the error is logged and the module is skipped for that buffer. The other modules
and the analysis carry on.

## Helpers (`api`)

Import helpers from `api`, not from `shellcode_check`, which can change between releases:

```python
from lib.cuckoo.common.integrations.shellcode_frameworks import api
```

| Helper | Use |
|---|---|
| `api.u16(buf, off)`, `api.u32(buf, off)` | little-endian reads (0 when out of range) |
| `api.find_embedded_pes(data, limit, max_hits)` | PE images in a buffer: `[{offset, nt_offset, arch, dll, ...}]` (offsets as hex strings) |
| `api.pe_raw_size(data, nt_offset)` | on-disk size of a PE from its headers (0 if unknown) |
| `api.extract_max()` | largest payload you may extract (bytes) |
| `api.region(start, size, result, result_type=..., source=..., status="structural")` | a Regions table entry. `result_type="pe"` marks a carried PE image (the `cape_shellcode_pe_loader` signature keys on it); `status="verified"` when you decrypted or decoded it and checked the result |
| `api.payload(extract, offset, description)` | a payload: `extract()` returns the bytes or `None` |

## Speed

`identify()` runs on **every** buffer the check analyses, mostly ones that are not your layout, so it
must reject them in microseconds:

- **Anchor first.** Start with a fixed-position byte check (`data[:4] == b"..."`), or a compiled
  `re` search bounded to a small window (`rx.search(data, 0, 0x1000)`). Do nothing expensive before
  the anchor matches.
- **No Python loops over the whole buffer.** Use `re`, `bytes.find`, slicing or `struct` (they run in C).
- **Defer heavy work to `extract()`.** Decryption and decompression of the payload belong in the
  `extract` callable. It only runs when payload extraction is enabled and the layout is identified.
  Check sizes against `api.extract_max()` before decrypting.
- Keep proof cheap: decrypt or decode only the few bytes you need to check (a header, a known
  plaintext), not the whole payload.

## Extracted payloads

Extracted payloads are stored as CAPE payloads and analysed again (a PE goes through the normal PE
processing, shellcode through this check again). The shipped frameworks have their own CAPE type codes
(0x2001 Donut, 0x2002 sRDI, 0x2003 pe2shc). Payloads from other modules use the generic 0x2005
"Extracted Shellcode Payload" type. The report records `framework` (your `NAME`) and your
`description` with it.

## Example

A loader that stores a magic, the payload offset and size, then XOR-encodes the payload with a
16-byte key held in the header:

```python
"""ExampleLoader: 'XLDR' magic, payload offset/size, 16-byte XOR key; proven when the decoded
payload starts with the loader's fixed 8-byte marker."""

from lib.cuckoo.common.integrations.shellcode_frameworks import api

NAME = "ExampleLoader"
FAMILY = "ExampleLoader"
MARKER = b"\x4d\x5a\x90\x00\x03\x00\x00\x00"  # what the decoded payload must start with


def _xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def identify(data):
    if data[:4] != b"XLDR":  # anchor: rejects other buffers immediately
        return None
    off, size, key = api.u32(data, 4), api.u32(data, 8), data[12:28]
    if not 28 <= off < off + size <= len(data):  # consistency: the fields fit the buffer
        return None
    if _xor(data[off : off + 8], key) != MARKER:  # proof: known plaintext after decoding 8 bytes
        return None

    def extract():
        if size > api.extract_max():
            return None
        return _xor(data[off : off + size], key)

    return {
        "confidence": "identified",
        "arch": "x64",
        "evidence": ["'XLDR' header; offset and size fit the buffer", "the key in the header decodes the payload marker"],
        "details": {"payload": "x64 EXE", "payload_size": size},
        "regions": [api.region(off, size, f"x64 EXE, {size} bytes, XOR-encoded", result_type="pe", source="XLDR header", status="verified")],
        "_payload": api.payload(extract, off, "ExampleLoader payload: x64 EXE"),
    }
```

## Testing a module

For each module:

1. **Positive:** a real sample, or one built from the generator. Check `confidence`, `details`, the
   regions and the extracted payload (`analyse(data, extract_payloads=True)["_payloads"]`).
2. **Negative:** the module must return `None` for other generators' output, for PE files, for
   random data, and for near misses (the right magic, but fields that do not fit).
3. **Speed:** time it over a few MB of unrelated data. It should take milliseconds.

`tests/test_shellcode_check.py` runs the shipped modules against these checks, and shows how to load a
module from a temporary folder (`dropped_frameworks` fixture) to test it the same way.
