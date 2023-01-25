# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


from lib.cuckoo.common.abstracts import Processing, Signature
from lib.cuckoo.common.constants import CUCKOO_VERSION


class ProcessingMock(Processing):
    def run(self):
        self.key = "foo"
        foo = {"bar": "taz"}
        return foo


class SignatureMock(Signature):
    name = "mock"
    minimum = CUCKOO_VERSION.split("-", 1)[0]
    maximum = CUCKOO_VERSION.split("-", 1)[0]

    def run(self, results):
        if "foo" in results:
            return True
        return False


class SignatureAlterMock(SignatureMock):
    def run(self, results):
        results = None  # noqa: F841


class SignatureDisabledMock(SignatureMock):
    enabled = False


class SignatureWrongVersionMock(SignatureMock):
    minimum = "0.0..-abc"
    maximum = "0.0..-abc"
