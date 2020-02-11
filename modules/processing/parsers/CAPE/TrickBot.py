# MIT License
#
# Copyright (c) 2017 Jason Reaves
# Copyright (c) 2019 Graham Austin
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
import pefile
import struct
import hashlib
from Crypto.Cipher import AES
import xml.etree.ElementTree as ET
import yara

rule_source = '''
rule TrickBot
{
    meta:
        author = "grahamaustin"
        description = "TrickBot Payload"
        cape_type = "TrickBot Payload"
    strings:
        $snippet1 = {B8 ?? ?? 00 00 85 C9 74 32 BE ?? ?? ?? ?? BA ?? ?? ?? ?? BF ?? ?? ?? ?? BB ?? ?? ?? ?? 03 F2 8B 2B 83 C3 04 33 2F 83 C7 04 89 29 83 C1 04 3B DE 0F 43 DA}
    condition:
        uint16(0) == 0x5A4D and ($snippet1)
}
'''

def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == 'TrickBot':
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
                    return addresses

def xor_data(data, key, key_len):
    i=0
    decrypted_blob = b""
    for x in range(0,len(data),4):
        xor = struct.unpack("<L", data[x:x+4])[0] ^ struct.unpack("<L",key[i % key_len])[0]
        decrypted_blob += struct.pack("<L", xor)
        i += 1
    return decrypted_blob

def derive_key(n_rounds,input_bf):
    intermediate = input_bf
    for i in range(0, n_rounds):
        sha = hashlib.sha256()
        sha.update(intermediate)
        current = sha.digest()
        intermediate += current
    return current

#expects a str of binary data open().read()
def trick_decrypt(data):
    key = derive_key(128, data[:32])
    iv = derive_key(128,data[16:48])[:16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    mod = len(data[48:]) % 16
    if mod != 0:
        data += '0' * (16 - mod)
    return aes.decrypt(data[48:])[:-(16-mod)]

def get_rsrc(pe):
    ret = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = str(resource_type.name)
            else:
                name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
            if name == None:
                name = str(resource_type.struct.name)
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData,resource_lang.data.struct.Size)
                            ret.append((name,data,resource_lang.data.struct.Size,resource_type))
    return ret

def va_to_fileoffset(pe, va):
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        if rva >= section.VirtualAddress and rva < section.VirtualAddress + section.Misc_VirtualSize:
            return rva - section.VirtualAddress + section.PointerToRawData

def decode_onboard_config(data):
    try:
        pe = pefile.PE(data=data)
        rsrcs = get_rsrc(pe)
    except:
        return

    if rsrcs != []:
        a = rsrcs[0][1]

        data = trick_decrypt(a[4:])
        length = struct.unpack_from('<I',data)[0]
        if length < 4000:
            return data[8:length+8]

        a = rsrcs[1][1]

        data = trick_decrypt(a[4:])
        length = struct.unpack_from('<I',data)[0]
        if length < 4000:
            return data[8:length+8]

    # Following code by grahamaustin
    snippet = yara_scan(data, '$snippet1')
    if not snippet:
        return
    offset = int(snippet['$snippet1'])
    key_len     = struct.unpack("<L", data[offset+10:offset+14])[0]
    key_offset  = struct.unpack("<L", data[offset+15:offset+19])[0]
    key_offset  = va_to_fileoffset(pe, int(struct.unpack("<L", data[offset+15:offset+19])[0]))
    data_offset = va_to_fileoffset(pe, int(struct.unpack("<L", data[offset+20:offset+24])[0]))
    size_offset = va_to_fileoffset(pe, int(struct.unpack("<L", data[offset+53:offset+57])[0]))
    size = size_offset - data_offset
    key = data[key_offset:key_offset+key_len]
    key = [key[i:i+4] for i in range(0, len(key), 4)]
    key_len2 = len(key)
    a = data[data_offset:data_offset+size]
    a = xor_data(a,key,key_len2)

    data = trick_decrypt(a)
    length = struct.unpack_from('<I',data)[0]
    if length < 4000:
        return data[8:length+8]

def config(data):
    xml = decode_onboard_config(data)
    try:
        root = ET.fromstring(xml)
    except:
        return
    raw_config = {}
    for child in root:

        if hasattr(child, 'key'):
            tag = child.attrib["key"]
        else:
            tag = child.tag

        if tag == 'autorun':
            val = str(map(lambda x: x.items(), child.getchildren()))
        elif tag == 'servs':
            val = (map(lambda x: x.text, child.getchildren()))
        else:
            val = child.text

        raw_config[tag] = val

    return raw_config
