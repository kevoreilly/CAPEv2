from lib.core.packages import _guess_package_name, choose_package_class
import pytest


@pytest.mark.parametrize("file_type, file_name, expected_package_name", [
    ("", "", None),
    ("Bourne-Again", None, "bash"),
    ("Zip archive", "sample.ZIP", "archive"),
    ("7-zip archive data", "sample.7z", "archive"),
    ("RAR archive data", "sample.rar", "archive"),
    ("POSIX tar archive", "sample.tar", "archive"),
    ("ISO 9660 CD-ROM filesystem data", "sample.iso", "archive"),
    ("gzip compressed data", "sample.tar.gz", "archive"),
    ("bzip2 compressed data", "sample.tbz2", "archive"),
    ("XZ compressed data", "sample.tar.xz", "archive"),
    ("PDF document", "test.pdf", "pdf"),
    ("Composite Document File V2 Document", "test.docx", "doc"),
    ("Microsoft Word", "test.docx", "doc"),
    ("ELF", None, "generic"),
    ("Unicode text", "malware.js", "js"),
])
def test__guess_package_name(file_type, file_name, expected_package_name):
    assert _guess_package_name(file_type, "") == expected_package_name, f"Expected {expected_package_name} for {file_type}, {file_name}"
    if file_name:
        assert _guess_package_name("", file_name) == expected_package_name, f"Expected {expected_package_name} for {file_type}, {file_name}"
        assert _guess_package_name(file_type, file_name) == expected_package_name, f"Expected {expected_package_name} for {file_type}, {file_name}"


@pytest.mark.parametrize("legacy_name", ["zip", "rar", "zip_compound", "archive"])
def test_choose_package_class_aliases_to_archive(legacy_name):
    pkg_class = choose_package_class(suggestion=legacy_name)
    assert pkg_class.__name__ == "Archive"
