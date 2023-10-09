import binascii
import logging
import os
import struct
from pathlib import Path

log = logging.getLogger(__name__)

try:
    import bson

    HAVE_BSON = True
except ImportError:
    HAVE_BSON = False
else:
    # The BSON module provided by pymongo works through its "BSON" class.
    if hasattr(bson, "BSON"):

        def bson_decode(d):
            return bson.BSON(d).decode()

    # The BSON module provided by "pip3 install bson" works through the
    # "loads" function (just like pickle etc.)
    elif hasattr(bson, "loads"):

        def bson_decode(d):
            return bson.loads(d)

    else:
        HAVE_BSON = False


class NGram:
    def __init__(self, order):
        self.order = order
        self.buffer = []

    def add(self, element):
        tmp = None
        if not element:
            return tmp

        if len(self.buffer) == self.order * 2:
            tmp = self.buffer.pop(0)

        if isinstance(element, list):
            self.buffer.append(element)
        else:
            self.buffer.append([element, 1])

        self.analyse()
        return tmp

    def analyse(self):
        tmp = [c[0][0] for c in self.buffer]
        if tmp[: self.order] == tmp[self.order :]:
            for i in range(self.order):
                self.buffer[i][1] += self.buffer[i + self.order][1]
            self.buffer = self.buffer[: self.order]


class Compressor:
    def __init__(self, level):
        self.level = level
        self.ngrams = [NGram(i) for i in range(1, level + 1)]
        self.final = []

    def add(self, element):
        head, tail = (self.ngrams[0], self.ngrams[1:])
        out = head.add(element)

        for t in tail:
            out = t.add(out)

        if out:
            self.final.append(out)

    def flush(self):
        for i, ngram in enumerate(self.ngrams):
            current_buffer = ngram.buffer
            for out in current_buffer:
                for u in range(i + 1, len(self.ngrams)):
                    out = self.ngrams[u].add(out)
                if out:
                    self.final.append(out)


class CuckooBsonCompressor:
    def __init__(self):
        self.threads = {}
        self.callmap = {}
        self.head = []
        self.ccounter = 0

    def __next_message(self):
        data = self.fd_in.read(4)
        if not data:
            return (False, False)
        _size = struct.unpack("I", data)[0]
        data += self.fd_in.read(_size - 4)
        self.raw_data = data
        return (data, bson_decode(data))

    def run(self, file_path):
        if not os.path.isfile(file_path) and os.stat(file_path).st_size:
            log.warning("File %s does not exists or it is invalid", file_path)
            return False

        self.fd_in = open(file_path, "rb")

        msg = "---"
        while msg:
            data, msg = self.__next_message()

            if msg:
                mtype = msg.get("type")  # message type [debug, new_process, info]
                if mtype in {"debug", "new_process", "info"}:
                    self.category = msg.get("category", "None")
                    self.head.append(data)

                elif self.category.startswith("__"):
                    self.head.append(data)
                else:
                    tid = msg.get("T", -1)
                    time = msg.get("t", 0)

                    if tid not in self.threads:
                        self.threads[tid] = Compressor(100)

                    csum = self.checksum(msg)
                    self.ccounter += 1
                    v = (csum, self.ccounter, time)
                    self.threads[tid].add(v)

                    if csum not in self.callmap:
                        self.callmap[csum] = msg
        self.fd_in.close()

        return self.flush(file_path)

    def flush(self, file_path):
        # This function flushes ngram buffers within compressor and merges
        # threads compressed call lists trying preserve original order

        compressed_path = f"{file_path}.compressed"
        p = Path(compressed_path)
        if p.is_file():
            p.unlink()

        fd = open(compressed_path, "wb")

        for d in self.head:
            fd.write(d)

        final = []
        for tid, c in self.threads.items():
            c.flush()
            for element, repeated in c.final:
                data = self.callmap.get(element[0]).copy()
                data["r"] += repeated
                data["t"] = element[2]
                data["order"] = element[1]
                final.append(data)

        final.sort(key=lambda x: x["order"])

        if final and os.path.isfile(compressed_path):
            for d in final:
                d.pop("order")
                edata = bson.BSON.encode(d)
                fd.write(edata)

            os.rename(file_path, f"{file_path}.raw")
            os.symlink(f"{file_path}.compressed", file_path)
        else:
            return False

        return True

    def checksum(self, msg):
        # This function calculates a 4 bytes checksum for each call
        # this value is used for identifying a call setup.

        index = msg.get("I", -1)
        args = "".join([str(c) for c in msg["args"]])
        content = [str(index), str(msg["T"]), str(msg["R"]), args, str(self.category), str(msg["P"])]

        content = "".join(content)

        return binascii.crc32(bytes(content, "utf8"))
