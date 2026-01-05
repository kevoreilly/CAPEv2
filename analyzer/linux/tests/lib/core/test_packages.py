from lib.core.packages import _guess_package_name
import pytest

@pytest.mark.parametrize("file_type, file_name, expected_package_name", [
    ("", "", None),
    ("Bourne-Again", None, "bash"),
    ("Zip archive", None, "zip"),
    ("gzip compressed data", None, "zip"),
    ("PDF document", "test.pdf", "pdf"),
    ("Composite Document File V2 Document", "test.docx", "doc"),
    ("Microsoft Word", "test.docx", "doc"),
    ("ELF", None, "generic"),
    ("Unicode text", "malware.js", "js")
])
def test__guess_package_name(file_type, file_name, expected_package_name):
    assert _guess_package_name(file_type, "") == expected_package_name, f"Expected {expected_package_name} for {file_type}, {file_name}"
    if file_name:
        assert _guess_package_name("", file_name) == expected_package_name, f"Expected {expected_package_name} for {file_type}, {file_name}"
        assert _guess_package_name(file_type, file_name) == expected_package_name, f"Expected {expected_package_name} for {file_type}, {file_name}"
