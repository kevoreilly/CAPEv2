import binascii
import logging
import mmap
import os
import struct
from pathlib import Path

log = logging.getLogger(__name__)

# bson from pymongo is C so is faster
try:
    import bson

    HAVE_BSON = True
except ImportError:
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
        self.category = None

    def _process_message(self, msg, data):
        mtype = msg.get("type")  # message type [debug, new_process, info]
        if mtype in {"debug", "new_process", "info"}:
            self.category = msg.get("category", "None")
            self.head.append(data.tobytes() if isinstance(data, memoryview) else data)

        elif self.category and self.category.startswith("__"):
            self.head.append(data.tobytes() if isinstance(data, memoryview) else data)
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

    def _process_mmap_content(self, mm):
        with memoryview(mm) as mv:
            offset = 0
            size_mm = len(mm)

            while offset < size_mm:
                # Read size (4 bytes)
                if offset + 4 > size_mm:
                    break

                # Slicing memoryview returns memoryview
                size_bytes = mv[offset : offset + 4]
                _size = struct.unpack("I", size_bytes)[0]

                if offset + _size > size_mm:
                    break

                data = mv[offset : offset + _size]
                offset += _size

                try:
                    msg = bson.decode(data)
                except Exception:
                    break

                if msg:
                    self._process_message(msg, data)

    def run(self, file_path, use_mmap=False):
        if use_mmap:
            return self._run_mmap(file_path)
        return self._run_standard(file_path)

    def _run_mmap(self, file_path):
        if not os.path.isfile(file_path) or not os.stat(file_path).st_size:
            log.warning("File %s does not exists or it is invalid", file_path)
            return False

        with open(file_path, "rb") as f:
            try:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            except ValueError:
                return False

            try:
                self._process_mmap_content(mm)
            finally:
                mm.close()

        return self.flush(file_path)

    def _run_standard(self, file_path):
        if not os.path.isfile(file_path) or not os.stat(file_path).st_size:
            log.warning("File %s does not exists or it is invalid", file_path)
            return False

        with open(file_path, "rb") as f:
            while True:
                size_bytes = f.read(4)
                if len(size_bytes) < 4:
                    break

                try:
                    _size = struct.unpack("I", size_bytes)[0]
                except struct.error:
                    break

                remaining = _size - 4
                if remaining < 0:
                    break

                data_body = f.read(remaining)
                if len(data_body) < remaining:
                    break

                data = size_bytes + data_body

                try:
                    msg = bson.decode(data)
                except Exception:
                    break

                if msg:
                    self._process_message(msg, data)

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
                edata = bson.encode(d)
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
        args = "".join(map(str, msg["args"]))
        content = f"{index}{msg['T']}{msg['R']}{args}{self.category}{msg['P']}"

        return binascii.crc32(content.encode("utf8"))


if __name__ == "__main__":
    import argparse
    import time
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to BSON file to compress")
    parser.add_argument("--mmap", action="store_true", help="Use mmap for compression")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"File {args.file} not found.")
        sys.exit(1)

    print(f"Compressing {args.file}...")
    start = time.time()

    compressor = CuckooBsonCompressor()
    result = compressor.run(args.file, use_mmap=args.mmap)

    end = time.time()

    if result:
        print(f"Compression successful. Took {end - start:.4f} seconds.")
    else:
        print("Compression failed.")
