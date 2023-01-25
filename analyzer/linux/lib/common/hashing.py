# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib

BUFSIZE = 1024 * 1024


def sha256_file(path):
    return hash_file(hashlib.sha256, path)


def hash_file(method, path):
    """Calculate a hash on a file by path.
    @param method: callable hashing method
    @param path: file path
    @return: computed hash string
    """
    h = method()
    with open(path, "rb") as f:
        buf = f.read(BUFSIZE)
        while buf:
            h.update(buf)
            buf = f.read(BUFSIZE)
    return h.hexdigest()
