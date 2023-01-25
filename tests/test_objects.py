# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import tempfile

import pytest
import yara

from lib.cuckoo.common.objects import Dictionary, File  # ,ProcDump
from lib.cuckoo.common.path_utils import path_delete, path_write_file

# from tcr_misc import get_sample, random_string


@pytest.fixture
def dict_cfg():
    yield Dictionary()


class TestDictionary:
    def test_usage(self, dict_cfg):
        dict_cfg.a = "foo"
        assert "foo" == dict_cfg.a
        dict_cfg.a = "bar"
        assert "bar" == dict_cfg.a

    def test_exception(self, dict_cfg):
        with pytest.raises(AttributeError):
            dict_cfg.b.a


@pytest.fixture
def empty_file():
    tmp = tempfile.mkstemp()
    file = File(tmp[1])
    yield {"tmp": tmp, "file": file}
    path_delete(tmp[1])


class TestEmptyFile:
    def test_get_name(self, empty_file):
        assert empty_file["tmp"][1].rsplit("/", 1)[-1] == empty_file["file"].get_name()

    def test_get_data(self, empty_file):
        assert empty_file["file"].get_data() == b""

    def test_get_size(self, empty_file):
        assert empty_file["file"].get_size() == 0

    def test_get_crc32(self, empty_file):
        assert empty_file["file"].get_crc32() == "00000000"

    def test_get_md5(self, empty_file):
        assert empty_file["file"].get_md5() == "d41d8cd98f00b204e9800998ecf8427e"

    def test_get_sha1(self, empty_file):
        assert empty_file["file"].get_sha1() == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def test_get_sha256(self, empty_file):
        assert empty_file["file"].get_sha256() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_get_sha512(self, empty_file):
        empty_file[
            "file"
        ].get_sha512() == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

    def test_get_ssdeep(self, empty_file):
        try:
            import pydeep  # noqa: F401

            assert empty_file["file"].get_ssdeep() is not None
        except ImportError:
            assert empty_file["file"].get_ssdeep() is None
            logging.warn("Need to install pydeep python module")

    def test_get_type(self, empty_file):
        assert empty_file["file"].get_type() == "empty"

    def test_get_content_type(self, empty_file):
        # Passing mime=True is not realistic, does not happen in prod code.
        assert empty_file["file"].get_content_type() == "empty"

    def test_get_all_type(self, empty_file):
        assert isinstance(empty_file["file"].get_all()[0], dict)

    def test_get_all_keys(self, empty_file):
        for key in ("name", "size", "crc32", "md5", "sha1", "sha256", "sha512", "ssdeep", "type"):
            assert key in empty_file["file"].get_all()[0]


""" ToDo ReEnable
@pytest.fixture(scope="class")
def test_files():
    test_files = [
        {
            "hash": "e3bb40e63e4b43a58037ce10b2f037486789b631c392cad01b42abd2bf6942d2",
            "source": "https://github.com/bootandy/dust/releases/download/v0.5.4/dust-v0.5.4-x86_64-pc-windows-msvc.zip",
            "get_type_str": "PE32+ executable (console) x86-64, for MS Windows",
            "comment": "dust.exe",
        },
        {
            "hash": "5dd87d3d6b9d8b4016e3c36b189234772661e690c21371f1eb8e018f0f0dec2b",
            "source": "https://github.com/bootandy/dust/releases/download/v0.5.4/dust-v0.5.4-i686-pc-windows-msvc.zip",
            "get_type_str": "PE32 executable (console) Intel 80386, for MS Windows",
            "comment": "dust.exe",
        },
        {
            "hash": "16ffc96e2de2ced2e8da611b8b3d4d02710df1714278203b67c2129987339bf2",
            "source": "https://www.scintilla.org/wscite32_446.zip",
            "get_type_str": "PE32 executable (GUI) Intel 80386, for MS Windows",
            "comment": "SciTE32.exe",
        },
        {
            "hash": "d0bfbe5a17a23e962814642508b397ff65a19a48156d516c723f5c233602c5e4",
            "source": "https://www.scintilla.org/wscite32_446.zip",
            "get_type_str": "PE32 executable (DLL) (GUI) Intel 80386, for MS Windows",
            "comment": "Scintilla.dll",
        },
        {
            "hash": "438117c7bd53653b3113903bcdb8bd369904a152b524b4676b18a626c2b60e82",
            "source": "https://www.scintilla.org/wscite446.zip",
            "get_type_str": "PE32+ executable (GUI) x86-64, for MS Windows",
            "comment": "SciTE.exe",
        },
        {
            "hash": "3782086dd779b883968053dd2cc65860b19678f3d323a39b7e6f47830ceb8632",
            "source": "https://www.scintilla.org/wscite446.zip",
            "get_type_str": "PE32+ executable (DLL) (GUI) x86-64, for MS Windows",
            "comment": "Scintilla.dll",
        },
        {
            "hash": "b70cb2dc500d4e507681d39e10bc554731fc177a5200b56f9844bd92a3168487",
            "source": "https://www.scintilla.org/wscite446.zip",
            "get_type_str": "PNG image data, 24 x 24, 8-bit grayscale, non-interlaced",
            "comment": "png",
        },
    ]

    random_suffix = random_string()

    test_files_with_location = test_files
    tmp_list = os.listdir(pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/")

    for index, _ in enumerate(test_files):
        sample_hash = test_files[index]["hash"]
        # do we already have a cached sample?
        cache = [x for x in tmp_list if sample_hash in x]
        if len(cache) > 0:
            print(("Already have " + sample_hash))
            test_files_with_location[index]["download_location"] = File(
                pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + cache[0]
            )
        else:
            sample_location = (
                pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sample_hash + "." + random_suffix
            )
            get_sample(hash=sample_hash, download_location=sample_location)
            test_files_with_location[index]["download_location"] = File(sample_location)
            print(("stored at " + sample_location))

    yield test_files_with_location

    if not os.environ.get("CACHE", True):
        for index, _ in enumerate(test_files_with_location):
            path_delete(test_files_with_location[index]["download_location"].file_path)

"""


@pytest.fixture
def hello_file():
    tmp = tempfile.mkstemp()
    file = File(tmp[1])
    _ = path_write_file(file.file_path, "hello", mode="text")
    yield {"tmp": tmp, "file": file}
    path_delete(tmp[1])


@pytest.fixture
def yara_compiled():
    yara_hello_source = """
        rule hello
        {
            strings:
                $a = "hello"
            condition:
                $a
        }
        """
    return yara.compile(source=yara_hello_source)


class TestFiles:
    @pytest.mark.skip(reason="TODO - init yara was removed from objects.py it was init in too many not related parts")
    def test_get_type(self, test_files):
        for sample in test_files:
            print(sample["download_location"], sample["download_location"].get_type(), sample["get_type_str"])
            assert sample["download_location"].get_type() == sample["get_type_str"]
            print(("Verified that " + sample["download_location"].file_path + " == " + sample["get_type_str"]))

    @pytest.mark.skip(reason="TODO - init yara was removed from objects.py it was init in too many not related parts")
    def test_get_yara(self, hello_file, yara_compiled):
        File.yara_rules = {"hello": yara_compiled}
        assert hello_file["file"].get_yara(category="hello") == [
            {"meta": {}, "addresses": {"a": 0}, "name": "hello", "strings": ["hello"]}
        ]

    @pytest.mark.skip(reason="TODO - init yara was removed from objects.py it was init in too many not related parts")
    def test_get_yara_no_categories(self, test_files):
        assert not test_files[0]["download_location"].get_yara()


class TestMisc:
    @pytest.mark.skip(reason="TODO - init yara was removed from objects.py it was init in too many not related parts")
    def test_yara_encode_string_deal_with_error(self):
        assert File("none_existent_file")._yara_encode_string("\xd0\x91") == "\xd0\x91"

    @pytest.mark.skip(reason="TODO - init yara was removed from objects.py it was init in too many not related parts")
    def test_yara_encode_string(self):
        assert File("none_existent_file")._yara_encode_string("velociraptor") == "velociraptor"


""" ToDo reenable
@pytest.fixture
def proc_dump():
    sha2 = "d62148b0329ac911ef707d6517e83b49416306198e343b28ab71343e30fa0075"
    location = pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + sha2 + "." + random_string()
    tmp_list = os.listdir(pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/")

    cache_list = [x for x in tmp_list if sha2 in x]
    if len(cache_list) > 0:
        print(("Already have " + sha2))
        location = pathlib.Path(__file__).absolute().parent.as_posix() + "/test_objects/" + cache_list[0]
    else:
        get_sample(hash=sha2, download_location=location)
    yield sha2, location
    if not os.environ.get("CACHE", True):
        os.unlink(location)



class TestProcDump:
    def test_init(self, proc_dump):
        assert ProcDump(dump_file=proc_dump[1])

    def test_get_data(self, proc_dump):
        data = ProcDump(dump_file=proc_dump[1]).get_data(addr=0, size=26)
        assert data == b"\xcd!This program cannot be r"

    def test_search_all(self, proc_dump):
        data = ProcDump(dump_file=proc_dump[1]).search(regex=rb"program", all=True)

        test_str = b"\xcd!This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00d\x94$S \xf5J\x00 \xf5J\x00 \xf5J\x00)\x8d\xdf\x00!\xf5J\x00)\x8d\xd9\x00-\xf5J\x00 \xf5K\x00F\xf5J\x00)\x8d\xce\x00#\xf5J\x00)\x8d\xc9\x005\xf5J\x00)\x8d\xde\x00!\xf5J\x00)\x8d\xdb\x00!\xf5J\x00Rich \xf5J\x00\x00\x00\x00\x00\x00\x00\x00\x00PE\x00\x00L\x01\x04\x00\t\x1d\xddX\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x02\x01\x0b\x01\t\x00\x00<\x00\x00\x00p\x00\x00\x00\x00\x00\x00\x98\x17\x00\x00\x00\x10\x00\x00\x00P\x00\x00\x00\x00I\x00\x00\x10\x00\x00\x00\x02\x00\x00\x06\x00\x01\x00\x06\x00\x01\x00\x06\x00\x01\x00"

        assert data["detail"][-1]["match"][0].string == test_str

    def test_search(self, proc_dump):
        data = ProcDump(dump_file=proc_dump[1]).search(regex=rb".*")

        test_str = b"@\x00\x00\x00"

        assert data["match"].string == test_str

    def test_parse_dump(self, proc_dump):
        test_dict = [
            {
                "end": 12894362193,
                "prot": 0,
                "start": 12894362189,
                "PE": False,
                "chunks": [
                    {
                        "end": 12894362193,
                        "prot": 0,
                        "start": 12894362189,
                        "state": 65535,
                        "offset": 24,
                        "type": 184,
                        "PE": False,
                        "size": 4,
                    }
                ],
                "size": 4,
            },
            {
                "end": 216,
                "prot": None,
                "start": 0,
                "PE": False,
                "chunks": [
                    {"end": 0, "prot": 0, "start": 0, "state": 0, "offset": 52, "type": 0, "PE": False, "size": 0},
                    {
                        "end": 216,
                        "prot": 1275181089,
                        "start": 0,
                        "state": 247078670,
                        "offset": 76,
                        "type": 3439965184,
                        "PE": False,
                        "size": 216,
                    },
                ],
                "size": 216,
            },
            {
                "end": 231309758694400,
                "prot": 262144,
                "start": 231309758693376,
                "PE": False,
                "chunks": [
                    {
                        "end": 231309758694400,
                        "prot": 262144,
                        "start": 231309758693376,
                        "state": 0,
                        "offset": 316,
                        "type": 2151677954,
                        "PE": False,
                        "size": 1024,
                    }
                ],
                "size": 1024,
            },
        ]
        assert ProcDump(dump_file=proc_dump[1]).parse_dump() == test_dict
"""
