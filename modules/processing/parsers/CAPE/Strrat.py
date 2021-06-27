# MIT License
#
# Copyright (c) 2021 enzok
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import
from __future__ import print_function
import zipfile
import base64
from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac

from lib.cuckoo.common.utils import store_temp_file


unpad = lambda s : s[0:-s[-1]]

def unzip_config(filepath):
    data = ""
    try:
        z = zipfile.ZipFile(filepath.decode('utf8'))
        for name in z.namelist():
            if "config.txt" in name:
                data = z.read(name)
                break
    except:
        return
    return data

def aesdecrypt(data, passkey):
    iv = data[4:20]
    key = pbkdf2_hmac("sha1", passkey, iv, 65536, 16)
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(data[20:]))

def decode(data):
    decoded = ""
    passkey = b"strigoi"
    try:
        data = base64.b64decode(data)
    except Exception as exc:
        return exc
    if data:
        try:
            decoded = aesdecrypt(data, passkey)
        except:
            return
    return decoded.decode('utf8')

def config(data):
    raw_config = {}
    configdata = ""
    tmpzip = store_temp_file(data, "badjar.zip", b"strrat_tmp")
    configdata = unzip_config(tmpzip)

    if configdata:
        raw_config["config"] = decode(configdata)

    return raw_config