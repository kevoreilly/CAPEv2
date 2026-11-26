"""Donut (github.com/TheWover/donut): the call over the DONUT_INSTANCE, the instance decrypted with
its own Chaskey key and checked against known plaintext, and the module it carries (decrypted and
decompressed on extraction)."""

import struct

from lib.cuckoo.common.integrations.shellcode_frameworks import api

try:  # optional: vectorised Chaskey for decrypting large Donut modules
    import numpy as np
except ImportError:  # pragma: no cover
    np = None

NAME = "Donut"
PRIORITY = 10

_M32 = 0xFFFFFFFF


def _rotr32(v, n):
    return ((v >> n) | (v << (32 - n))) & _M32


def _chaskey(mk, block):
    """Chaskey-LTS block encryption as used by Donut (16 rounds)."""
    k = struct.unpack("<4I", mk)
    w = [a ^ b for a, b in zip(struct.unpack("<4I", block), k)]
    for _ in range(16):
        w[0] = (w[0] + w[1]) & _M32
        w[1] = _rotr32(w[1], 27) ^ w[0]
        w[2] = (w[2] + w[3]) & _M32
        w[3] = _rotr32(w[3], 24) ^ w[2]
        w[2] = (w[2] + w[1]) & _M32
        w[0] = (_rotr32(w[0], 16) + w[3]) & _M32
        w[3] = _rotr32(w[3], 19) ^ w[0]
        w[1] = _rotr32(w[1], 25) ^ w[2]
        w[2] = _rotr32(w[2], 16)
    return struct.pack("<4I", *(a ^ b for a, b in zip(w, k)))


def _ctr_read(mk, ctr, data, start, off, n):
    """n plaintext bytes at off of a Chaskey-CTR stream starting at start (big-endian
    128-bit counter). CTR allows decrypting only the blocks that are needed."""
    rel = off - start
    first, last = rel // 16, (rel + n + 15) // 16
    c0 = int.from_bytes(ctr, "big")
    out = bytearray()
    for b in range(first, last):
        ks = _chaskey(mk, ((c0 + b) & ((1 << 128) - 1)).to_bytes(16, "big"))
        out += bytes(x ^ y for x, y in zip(data[start + 16 * b : start + 16 * b + 16], ks))
    skip = rel - 16 * first
    return bytes(out[skip : skip + n])


def _chaskey_stream(mk, c0, nblocks):
    """Chaskey-CTR keystream for nblocks blocks from counter c0 (pure Python, inlined rounds)."""
    k0, k1, k2, k3 = struct.unpack("<4I", mk)
    unpack, pack, m = struct.Struct("<4I").unpack, struct.Struct("<4I").pack, _M32
    out = []
    for b in range(nblocks):
        w0, w1, w2, w3 = unpack(((c0 + b) & ((1 << 128) - 1)).to_bytes(16, "big"))
        w0, w1, w2, w3 = w0 ^ k0, w1 ^ k1, w2 ^ k2, w3 ^ k3
        for _ in range(16):
            w0 = (w0 + w1) & m
            w1 = ((w1 >> 27) | (w1 << 5)) & m ^ w0
            w2 = (w2 + w3) & m
            w3 = ((w3 >> 24) | (w3 << 8)) & m ^ w2
            w2 = (w2 + w1) & m
            w0 = ((((w0 >> 16) | (w0 << 16)) & m) + w3) & m
            w3 = ((w3 >> 19) | (w3 << 13)) & m ^ w0
            w1 = ((w1 >> 25) | (w1 << 7)) & m ^ w2
            w2 = ((w2 >> 16) | (w2 << 16)) & m
        out.append(pack(w0 ^ k0, w1 ^ k1, w2 ^ k2, w3 ^ k3))
    return b"".join(out)


def _chaskey_stream_np(mk, c0, nblocks):
    """The same keystream, vectorised over all blocks with numpy."""
    b = np.arange(nblocks, dtype=np.uint64)
    lo0, hi0 = np.uint64(c0 & (2**64 - 1)), np.uint64((c0 >> 64) & (2**64 - 1))
    lo = lo0 + b  # wraps; the carry goes into the high half of the 128-bit big-endian counter
    hi = hi0 + (lo < lo0).astype(np.uint64)
    blocks = np.empty((nblocks, 2), dtype=">u8")
    blocks[:, 0], blocks[:, 1] = hi, lo
    w = blocks.view("<u4").reshape(-1, 4).astype(np.uint32)
    k = np.frombuffer(mk, dtype="<u4").astype(np.uint32)
    w ^= k

    def rotr(v, r):
        return (v >> np.uint32(r)) | (v << np.uint32(32 - r))

    v0, v1, v2, v3 = (w[:, i].copy() for i in range(4))
    for _ in range(16):
        v0 += v1
        v1 = rotr(v1, 27) ^ v0
        v2 += v3
        v3 = rotr(v3, 24) ^ v2
        v2 += v1
        v0 = rotr(v0, 16) + v3
        v3 = rotr(v3, 19) ^ v0
        v1 = rotr(v1, 25) ^ v2
        v2 = rotr(v2, 16)
    return (np.stack((v0, v1, v2, v3), axis=1) ^ k).astype("<u4").tobytes()


def _ctr_decrypt(mk, ctr, data, start, off, n):
    """_ctr_read for whole payloads (numpy when available: ~30x faster on multi-MB modules)."""
    rel = off - start
    first, last = rel // 16, (rel + n + 15) // 16
    c0 = int.from_bytes(ctr, "big") + first
    ks = (_chaskey_stream_np if np is not None and n >= 4096 else _chaskey_stream)(mk, c0, last - first)
    lo = start + 16 * first
    enc = bytes(data[lo : lo + len(ks)])
    plain = (int.from_bytes(enc, "little") ^ int.from_bytes(ks[: len(enc)], "little")).to_bytes(len(enc), "little")
    skip = rel - 16 * first
    return plain[skip : skip + n]


def _xpress_lz77(src, size):
    """Plain LZ77 Xpress (MS-XCA 2.3, COMPRESSION_FORMAT_XPRESS) decompression, capped at size bytes."""
    out = bytearray()
    i, flags, nflags, half = 0, 0, 0, None
    end = len(src)
    while i < end and len(out) < size:
        if nflags == 0:
            if i + 4 > end:
                break
            flags, nflags, i = api.u32(src, i), 32, i + 4
        nflags -= 1
        if not flags >> nflags & 1:
            if i >= end:
                break
            out.append(src[i])
            i += 1
            continue
        if i + 2 > end:
            break
        match = src[i] | src[i + 1] << 8
        i += 2
        length, dist = match & 7, (match >> 3) + 1
        if length == 7:
            if half is None:
                if i >= end:
                    break
                length, half, i = src[i] & 0xF, i, i + 1
            else:
                length, half = src[half] >> 4, None
            if length == 15:
                if i >= end:
                    break
                length, i = src[i], i + 1
                if length == 255:
                    if i + 2 > end:
                        break
                    length, i = src[i] | src[i + 1] << 8, i + 2
                    if length == 0:
                        if i + 4 > end:
                            break
                        length, i = api.u32(src, i), i + 4
                    if length < 22:
                        raise ValueError("invalid Xpress match length")
                    length -= 22
                length += 15
            length += 7
        length += 3
        if dist > len(out):
            raise ValueError("Xpress match before the start of the output")
        if dist >= length:
            out += out[-dist : len(out) - dist + length]
        else:
            for _ in range(length):
                out.append(out[-dist])
    return bytes(out[:size])


def _decompress(method, src, size):
    """Donut module compression: aPLib, LZNT1 or plain LZ77 Xpress (RtlDecompressBuffer format compress-1)."""
    if method == "aPLib":
        from cape_parsers.utils.aplib import decompress
    elif method == "LZNT1":
        from cape_parsers.utils.lznt1 import decompress_data as decompress
    elif method == "Xpress":
        return _xpress_lz77(src, size)
    else:
        return None
    out = decompress(bytes(src))
    return out[:size] if out else None


# Donut (github.com/TheWover/donut, donut.c / include/donut.h): E8 <len> <DONUT_INSTANCE> 59 <arch stub>
DONUT_ARCH_STUBS = {
    b"\x59\x5a\x51\x52": "x86",  # pop ecx; pop edx; push ecx; push edx
    b"\x59\x55\x48\x89\xe5\x48\x83\xe4\xf0\x48\x83\xec\x20": "x64",  # pop rcx; LOADER_EXE_X64_RSP_ALIGN
    b"\x59\x31\xc0\x48\x0f\x88": "x86+x64",  # pop ecx; xor eax, eax; dec eax / js (architecture switch)
}
# DONUT_INSTANCE / DONUT_MODULE offsets (Donut 1.x; the same layout Unit 42 documents for an
# in-the-wild sample). Everything from api_cnt on is encrypted with the key stored at +4.
DONUT_INSTANCE = {"key": 0x04, "api_cnt": 0x23C, "dll_names": 0x240, "bypass": 0x570, "headers": 0x574, "type": 0x920,
                  "server": 0x924, "mod_len": 0xD58, "module": 0xD60}  # fmt: skip
DONUT_BYPASS = {1: "no", 2: "yes (stop if it fails)", 3: "yes (continue if it fails)"}  # AMSI/WLDP/ETW
DONUT_HEADERS = {1: "overwritten after loading", 2: "kept"}  # the mapped PE's headers
DONUT_MODULE = {"type": 0x0, "compress": 0x8, "runtime": 0xC, "cls": 0x20C, "method": 0x30C, "zlen": 0x520,
                "len": 0x524, "data": 0x528}  # fmt: skip
DONUT_DLL_NAMES = b"ole32;oleaut32;wininet;mscoree;shell32"  # known plaintext at dll_names
DONUT_MODULE_TYPES = {1: ".NET DLL", 2: ".NET EXE", 3: "DLL", 4: "EXE", 5: "VBScript", 6: "JScript"}
DONUT_COMPRESSION = {1: None, 2: "aPLib", 3: "LZNT1", 4: "Xpress"}
DONUT_INSTANCE_TYPES = {1: "embedded", 2: "HTTP", 3: "DNS"}


def _cstr(raw):
    return raw.split(b"\0", 1)[0].decode("latin-1", "replace")


def identify(data):
    if len(data) < 0x40 or data[0] != 0xE8:
        return None
    n = api.u32(data, 1)
    if n < DONUT_INSTANCE["module"] or api.u32(data, 5) != n or 5 + n + 16 > len(data):
        return None
    arch = next((a for stub, a in DONUT_ARCH_STUBS.items() if data[5 + n : 5 + n + len(stub)] == stub), None)
    if arch is None:
        return None
    base = 5
    fw = {"name": "Donut", "confidence": "identified", "arch": arch,
          "evidence": [f"call over the instance ({n} bytes); its length field matches",
                       f"Donut's {arch} loader stub follows the instance at {5 + n:#x}"],
          "details": {}, "regions": [], "iocs": {}}  # fmt: skip
    region = {"start": base, "size": n, "status": "structural", "framework": "Donut",
              "source": "call over the instance at 0x0", "result_type": "instance", "result": "Donut instance",
              "entropy": None, "decoded_entropy": None}  # fmt: skip
    fw["regions"].append(region)
    mk, ctr = data[base + 4 : base + 20], data[base + 20 : base + 36]
    start = base + DONUT_INSTANCE["api_cnt"]
    names_at = base + DONUT_INSTANCE["dll_names"]
    if data[names_at : names_at + len(DONUT_DLL_NAMES)] == DONUT_DLL_NAMES:
        encrypted = False

        def read(off, k):
            return data[base + off : base + off + k]

    elif _ctr_read(mk, ctr, data, start, names_at, len(DONUT_DLL_NAMES)) == DONUT_DLL_NAMES:
        encrypted = True

        def read(off, k):
            return _ctr_read(mk, ctr, data, start, base + off, k)

    else:
        # layout matches but the known plaintext does not (another Donut version): no payload details
        region["result"] = "Donut instance (layout of another Donut version: not decoded)"
        return fw
    fw["evidence"].append(
        ("decrypting with the instance's own Chaskey key gives" if encrypted else "plaintext instance holds")
        + " Donut's DLL list 'ole32;oleaut32;wininet;mscoree;shell32'"
    )
    fw["details"]["instance"] = "encrypted with Chaskey-CTR, key stored in the instance" if encrypted else "not encrypted"
    itype = api.u32(read(DONUT_INSTANCE["type"], 4), 0)
    fw["details"]["instance_type"] = DONUT_INSTANCE_TYPES.get(itype, str(itype))
    bypass = DONUT_BYPASS.get(api.u32(read(DONUT_INSTANCE["bypass"], 4), 0))
    if bypass:
        fw["details"]["amsi_wldp_etw_bypass"] = bypass
    headers = DONUT_HEADERS.get(api.u32(read(DONUT_INSTANCE["headers"], 4), 0))
    if itype != 1:
        url = _cstr(read(DONUT_INSTANCE["server"], 256))
        if url:
            fw["details"]["staging_url"] = url
            fw["iocs"]["urls"] = [url]
        region["result"] = (
            f"Donut instance, {'encrypted' if encrypted else 'not encrypted'}; payload staged from {url or 'a server'}"
        )
        return fw
    mod = base + DONUT_INSTANCE["module"]
    head = read(DONUT_INSTANCE["module"], DONUT_MODULE["data"] + 0x400)
    mtype, comp = api.u32(head, DONUT_MODULE["type"]), api.u32(head, DONUT_MODULE["compress"])
    zlen, plen = api.u32(head, DONUT_MODULE["zlen"]), api.u32(head, DONUT_MODULE["len"])
    kind = DONUT_MODULE_TYPES.get(mtype)
    if kind is None or plen == 0 or plen > len(data) * 64:
        region["result"] = "Donut instance (module header not recognised)"
        return fw
    compression = DONUT_COMPRESSION.get(comp, f"type {comp}")
    payload = head[DONUT_MODULE["data"] :]
    if not compression:
        pes = api.find_embedded_pes(payload, len(payload), 1)
        if pes and pes[0]["offset"] == "0x0":
            kind = f"{pes[0]['arch']} {kind}"
    stored = zlen if compression else plen
    fw["details"].update({"payload": kind, "payload_size": plen})
    if headers and mtype in (3, 4):  # unmanaged PEs are mapped by the loader itself
        fw["details"]["pe_headers"] = headers
    for k in ("runtime", "cls", "method"):
        v = _cstr(head[DONUT_MODULE[k] : DONUT_MODULE[k] + 256])
        if v:
            fw["details"][{"cls": "class"}.get(k, k)] = v
    what = f"{kind}, {plen} bytes"
    if compression:
        fw["details"]["compression"] = f"{compression} ({zlen} -> {plen} bytes)"
        what += f", {compression}-compressed to {zlen}"
    region["result"] = f"Donut instance, {'encrypted' if encrypted else 'not encrypted'}; payload: {what}"
    src = mod + DONUT_MODULE["data"]

    def extract():
        if stored > api.extract_max() or plen > api.extract_max() or src + stored > len(data):
            return None
        raw = _ctr_decrypt(mk, ctr, data, start, src, stored) if encrypted else data[src : src + stored]
        if compression:
            raw = _decompress(compression, raw, plen)
        return bytes(raw) if raw and len(raw) == plen else None

    fw["_payload"] = {"extract": extract, "offset": src, "description": f"Donut module: {kind}"}
    fw["regions"].append(
        {
            "start": mod + DONUT_MODULE["data"],
            "size": stored,
            "status": "verified" if encrypted else "structural",
            "framework": "Donut",
            "source": "DONUT_MODULE.data (sizes from the module header)",
            "result_type": "pe" if "EXE" in kind or "DLL" in kind else "script",
            "result": what,
            "entropy": None,
            "decoded_entropy": None,
        }  # fmt: skip
    )
    return fw
