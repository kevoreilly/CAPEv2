# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

BUFSIZE = 1024 * 1024


def hash_file(method, path):
    """Calculates an hash on a file by path.
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
