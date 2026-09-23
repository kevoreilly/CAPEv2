import io
import marshal
import os
import struct
import sys
import zlib

from lib.cuckoo.common.integrations.pyinstxtractor import CTOCEntry, PyInstArchive


def _build_toc_entry(entry_pos: int, data: bytes, type_flag: bytes, name: bytes, compressed: int = 1) -> bytes:
    cmprsd = zlib.compress(data) if compressed else data
    header_size = struct.calcsize("!iIIIBc")
    name_padded = name + b"\x00"
    entry_size = header_size + len(name_padded)
    return struct.pack(
        f"!iIIIBc{len(name_padded)}s",
        entry_size,
        entry_pos,
        len(cmprsd),
        len(data),
        compressed,
        type_flag,
        name_padded,
    )


def test_parse_toc_and_extract_files_path_traversal(tmp_path):
    dest_dir = tmp_path / "extracted"
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    payload = b"MARSHALED_CODE_PAYLOAD"
    compressed_payload = zlib.compress(payload)

    entries_raw = b"".join(
        [
            _build_toc_entry(0, payload, b"s", b"../../../../outside/pwn_rel"),
            _build_toc_entry(0, payload, b"s", b"%2e%2e/%2e%2e/outside/pwn_url"),
            _build_toc_entry(0, payload, b"s", b"\\..\\..\\outside\\pwn_win"),
            _build_toc_entry(0, payload, b"s", str(outside_dir / "pwn_abs").encode()),
            _build_toc_entry(0, payload, b"M", b"pkg/module_ok"),
        ]
    )

    stream = io.BytesIO(compressed_payload + entries_raw)
    arch = PyInstArchive(
        {
            "file": str(tmp_path / "dummy.exe"),
            "destination_folder": str(dest_dir),
            "entry_points": False,
        }
    )
    arch.fPtr = stream
    arch.overlayPos = 0
    arch.tableOfContentsPos = len(compressed_payload)
    arch.tableOfContentsSize = len(entries_raw)
    arch.pymaj = sys.version_info.major
    arch.pymin = sys.version_info.minor
    arch.pycMagic = b"\x42\x0d\x0d\x0a"

    arch.parseTOC()
    arch.extractFiles()

    # Verify nothing was written to outside_dir
    assert list(outside_dir.iterdir()) == []

    # Verify all created files reside strictly under dest_dir
    dest_real = os.path.realpath(str(dest_dir))
    extracted_files = []
    for root, _, files in os.walk(dest_dir):
        for fname in files:
            full_path = os.path.realpath(os.path.join(root, fname))
            assert full_path.startswith(dest_real + os.sep)
            extracted_files.append(os.path.relpath(full_path, dest_real))

    assert "pkg/module_ok.pyc" in extracted_files


def test_extract_pyz_leading_dot_and_slash_traversal(tmp_path):
    """Verify _extractPyz cannot escape dirName when TOC keys start with '.', '/', or '\\'."""
    dest_dir = tmp_path / "extracted"
    dest_dir.mkdir()
    outside_target = tmp_path / "escaped_from_pyz"
    outside_target.mkdir()

    payload = zlib.compress(b"PYZ_BYTECODE")
    # Build a synthetic PYZ archive in-memory on disk
    pyz_path = dest_dir / "archive.pyz"

    # Header: b"PYZ\0" (4B) + magic (4B) + toc_pos (4B) + payload + marshaled TOC
    data_offset = 12
    # Before this fix, a leading single dot like ".tmp.pwn" turned into "/tmp/pwn" via .replace(".", os.path.sep),
    # causing os.path.join(dirName, fileName + ".pyc") to discard dirName and write to /tmp/pwn.pyc!
    leading_dot_key = "." + str(outside_target).lstrip("/").replace("/", ".") + ".dot_escape"
    leading_slash_key = str(outside_target / "slash_escape")
    leading_backslash_key = "\\" + str(outside_target / "backslash_escape").lstrip("/").replace("/", "\\")

    toc_dict = {
        leading_dot_key.encode(): (0, data_offset, len(payload)),
        leading_slash_key.encode(): (0, data_offset, len(payload)),
        leading_backslash_key.encode(): (1, data_offset, len(payload)),
        b"../../outside/rel_escape": (0, data_offset, len(payload)),
        b"legit.pkg.submodule": (0, data_offset, len(payload)),
    }
    marshaled_toc = marshal.dumps(toc_dict)
    toc_pos = data_offset + len(payload)

    with open(pyz_path, "wb") as f:
        f.write(b"PYZ\0")
        f.write(b"\x42\x0d\x0d\x0a")
        f.write(struct.pack("!i", toc_pos))
        f.write(payload)
        f.write(marshaled_toc)

    arch = PyInstArchive(
        {
            "file": str(tmp_path / "dummy.exe"),
            "destination_folder": str(dest_dir),
            "entry_points": False,
        }
    )
    arch.pymaj = sys.version_info.major
    arch.pymin = sys.version_info.minor
    arch.pycMagic = b"\x42\x0d\x0d\x0a"

    arch._extractPyz(str(pyz_path))

    # Ensure nothing escaped into outside_target
    assert list(outside_target.iterdir()) == []

    # Ensure everything written is strictly inside archive.pyz_extracted
    pyz_extracted_dir = pyz_path.parent / "archive.pyz_extracted"
    assert pyz_extracted_dir.is_dir()
    assert (pyz_extracted_dir / "legit" / "pkg" / "submodule.pyc").is_file()


def test_extract_files_blocks_symlink_escape(tmp_path):
    dest_dir = tmp_path / "extracted"
    dest_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    # Create a symlink inside dest_dir pointing to outside_dir
    symlink_dir = dest_dir / "sublink"
    symlink_dir.symlink_to(outside_dir, target_is_directory=True)

    payload = b"SYMLINK_PAYLOAD"
    compressed = zlib.compress(payload)

    arch = PyInstArchive(
        {
            "file": str(tmp_path / "dummy.exe"),
            "destination_folder": str(dest_dir),
            "entry_points": True,
        }
    )
    arch.fPtr = io.BytesIO(compressed)
    arch.pymaj = sys.version_info.major
    arch.pymin = sys.version_info.minor
    arch.pycMagic = b"\x42\x0d\x0d\x0a"
    arch.tocList = [
        CTOCEntry(0, len(compressed), len(payload), 1, b"s", "sublink/escaped_via_symlink"),
    ]

    arch.extractFiles()

    # Verify symlink escape was blocked and nothing was written to outside_dir
    assert list(outside_dir.iterdir()) == []
