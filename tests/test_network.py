# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import modules.processing.network as net


def test_batch_sort_stages_chunks_in_cape_external_and_cleans_up(tmp_path, monkeypatch):
    ext_dir = tmp_path / "cape-external"
    ext_dir.mkdir()
    monkeypatch.setattr(net, "get_cape_external_dir", lambda: str(ext_dir))

    seen_chunk_paths = []

    class _Item:
        def __init__(self, val):
            self.obj = val

        def __lt__(self, other):
            return self.obj < other.obj

    class _MemChunk:
        _store = {}

        def __init__(self, path):
            self.name = path
            if path != str(tmp_path / "out.bin"):
                seen_chunk_paths.append(path)
            self._store.setdefault(path, [])

        def write(self, val=None):
            if val is not None:
                self._store[self.name].append(val)

        def close(self):
            pass

        def __iter__(self):
            return iter(_Item(v) for v in self._store.get(self.name, []))

    out_path = str(tmp_path / "out.bin")
    net.batch_sort(iter([_Item(3), _Item(1), _Item(2)]), out_path, buffer_size=2, output_class=_MemChunk)

    assert len(seen_chunk_paths) == 2
    assert all(p.startswith(str(ext_dir)) for p in seen_chunk_paths)
    assert list(ext_dir.iterdir()) == []
    assert _MemChunk._store[out_path] == [1, 2, 3]
